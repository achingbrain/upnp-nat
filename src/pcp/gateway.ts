import { randomBytes } from 'crypto'
import { createSocket } from 'dgram'
import { EventEmitter } from 'events'
import { isIPv4, isIPv6 } from '@chainsafe/is-ip'
import { logger } from '@libp2p/logger'
import errCode from 'err-code'
import defer, { type DeferredPromise } from 'p-defer'
import { raceSignal } from 'race-signal'
import { DEFAULT_REFRESH_TIMEOUT } from '../upnp/constants.js'
import { findLocalAddresses } from '../upnp/utils.js'
import { isPrivateIp, to16ByteIP } from '../utils.js'
import type { Gateway, GlobalMapPortOptions, PortMapping, PCPMapPortOptions, Protocol } from '../index.js'
import type { AbortOptions } from 'abort-error'
import type { Socket, RemoteInfo } from 'dgram'

const log = logger('nat-port-mapper:pcp')

// Ports defined by rfc6887
const CLIENT_PORT = 5350
const SERVER_PORT = 5351

// Version defined by rfc6887
const PCP_VERSION = 2

// Opcodes
const OP_ANNOUNCE = 0
const OP_MAP = 1
const OP_PEER = 2

// Bits
const RESERVED_BIT = 0

// Protocols
const PROTO_TCP = 0x06
const PROTO_UDP = 0x11

const EMPTY_IPV4 = '0.0.0.0'
const EMPTY_IPV6 = '0000:0000:0000:0000:0000:0000:0000:0000'
const DISCARD_PORT = 9
const MINIMUM_LIFETIME = 120

const DEFAULT_PCP_PORT_MAPPING_TTL = 60 * 60 // 1 hour

// Result codes
const RESULT_CODES: Record<number, string> = {
  0: 'Success',
  1: 'Unsupported Version', // indicates that the client should fall back to using NAT-PMP
  2: 'Not Authorized/Refused (gateway may have NAT-PCP disabled)',
  3: 'Malformed request',
  4: 'Unsupported opcode',
  5: 'Unsupported option',
  6: 'Malformed option',
  7: 'Network failure',
  8: 'Out of Resources (no ports left)',
  9: 'Unsupported protocol',
  10: 'Exceeded port quota',
  11: 'External port and/or external address cannot be provided',
  12: 'Address mismatch (Source ip address does not match requested PCP client address. Possibly using the wrong IP address e.g. IPv6 deprecated addresses or there is a NAT between the client and server)',
  13: 'Excessive remote peers'
}

interface MappingNonce {
  protocol: Protocol
  internalHost: string
  internalPort: number
  externalHost?: string
  externalPort?: number
  nonce: Buffer
  expiresAt?: number
}

export type MappingNonces = MappingNonce[]

export class PCPGateway extends EventEmitter implements Gateway {
  public id: string
  private readonly socket: Socket
  private queue: Array<{ op: number, buf: Uint8Array, deferred: DeferredPromise<any> }>
  private connecting: boolean
  private listening: boolean
  private req: any
  private reqActive: boolean
  public readonly host: string
  public readonly port: number
  public readonly family: 'IPv4' | 'IPv6'
  private readonly options: GlobalMapPortOptions
  private readonly refreshIntervals: Map<number, ReturnType<typeof setTimeout>>
  private mappingNonces: MappingNonces

  constructor (gateway: string, options: GlobalMapPortOptions = {}) {
    super()

    this.queue = []
    this.connecting = false
    this.listening = false
    this.req = null
    this.reqActive = false
    this.host = gateway
    this.port = SERVER_PORT
    this.family = isIPv4(gateway) ? 'IPv4' : 'IPv6'
    this.id = this.host
    this.options = options
    this.refreshIntervals = new Map()
    this.mappingNonces = []

    // Create socket
    if (isIPv4(gateway)) {
      this.socket = createSocket({ type: 'udp4', reuseAddr: true })
    } else if (isIPv6(gateway)) {
      this.socket = createSocket({ type: 'udp6', reuseAddr: true })
    } else {
      throw new Error('unknown gateway type')
    }

    this.socket.on('listening', () => { this.onListening() })
    this.socket.on('message', (msg, rinfo) => { this.onMessage(msg, rinfo) })
    this.socket.on('close', () => { this.onClose() })
    this.socket.on('error', (err) => { this.onError(err) })

    // Try to connect
    this.connect()
  }

  connect (): void {
    log('Client#connect()')
    if (this.connecting) return
    this.connecting = true
    this.socket.bind(0) // use a random port as per spec
  }

  async * mapAll (internalPort: number, options: PCPMapPortOptions): AsyncGenerator<PortMapping, void, unknown> {
    let mapped = false

    for (const host of findLocalAddresses(this.family)) {
      try {
        log('mapping host', host)
        options.clientAddress = host
        const mapping = await this.map(internalPort, host, options)
        mapped = true

        yield mapping
      } catch (err) {
        log.error('error mapping %s:%d - %e', host, internalPort, err)
      }
    }

    if (!mapped) {
      throw new Error(`All attempts to map port ${internalPort} failed`)
    }
  }

  async map (internalPort: number, internalHost: string, opts: PCPMapPortOptions): Promise<PortMapping> {
    const options = {
      clientAddress: internalHost,
      publicPort: opts?.suggestedExternalPort ?? internalPort,
      publicHost: opts?.suggestedExternalAddress ?? '',
      protocol: opts?.protocol ?? 'tcp',
      ttl: opts?.ttl ?? this.options.ttl ?? DEFAULT_PCP_PORT_MAPPING_TTL,
      autoRefresh: opts?.autoRefresh ?? this.options.autoRefresh ?? true,
      refreshTimeout: opts?.refreshTimeout ?? this.options.refreshTimeout ?? DEFAULT_REFRESH_TIMEOUT
    }

    log('Client#portMapping()')
    switch (options.protocol.toLowerCase()) {
      case 'tcp':
        break
      case 'udp':
        break
      default:
        throw new Error('"type" must be either "tcp" or "udp"')
    }

    const deferred = defer<{ resultCode: number, internalHost: string, internalPort: number, externalAddress: string, externalPort: number, lifetime: number, protocol: 'TCP' | 'UDP' }>()

    this.request(OP_MAP, deferred, internalPort, options)

    let result
    try {
      result = await raceSignal(deferred.promise, opts?.signal)
    } catch (e: any) {
      this.deleteMappingNonce(internalHost, internalPort, options.protocol)
      throw e
    }

    if (options.autoRefresh) {
      // TODO
      const refresh = ((internalPort: number, opts: PCPMapPortOptions): void => {
        log(`refreshing port mapping for ip: ${internalHost} port: ${internalPort} protocol: ${options.protocol}`)
        const mn = this.getMappingNonce(internalHost, internalPort, options.protocol)
        if (mn === undefined) {
          throw new Error('Could not find mapping to renew')
        }

        opts.suggestedExternalAddress = mn.externalHost
        opts.suggestedExternalPort = mn.externalPort
        this.map(internalPort, internalHost, {
          ...opts,
          signal: AbortSignal.timeout(options.refreshTimeout)
        })
          .catch(err => {
            log.error('could not refresh port mapping - %e', err)
          })
      }).bind(this, internalPort, {
        ...options,
        signal: undefined
      })

      this.refreshIntervals.set(internalPort, setTimeout(refresh, (result.lifetime / 2) * 1000))
    }

    return {
      externalHost: isPrivateIp(internalHost) === true ? await this.externalIp(opts) : internalHost,
      externalPort: result.externalPort,
      internalHost,
      internalPort: result.internalPort,
      protocol: result.protocol
    }
  }

  async unmap (localPort: number, opts: PCPMapPortOptions): Promise<void> {
    // TODO
    log('Client#portUnmapping()')

    await this.map(localPort, opts.clientAddress, {
      ...opts,
      ttl: 0
    })
  }

  async externalIp (options?: AbortOptions): Promise<string> {
    // Create a short lived map to get the external IP as recommeneded by the
    // spec 11.6 Learning the External IP Address Alone. It should be OK for
    // residential NATs but Carrier-Grade NATs may use a pool of addresses so
    // the external address isn't guaranteed.

    for (const host of findLocalAddresses(this.family)) {
      const opts: PCPMapPortOptions = {
        clientAddress: host,
        ttl: MINIMUM_LIFETIME,
        autoRefresh: false
      }

      let externalIp: string | undefined

      try {
        const mapping = await this.map(DISCARD_PORT, host, opts)
        externalIp = mapping.externalHost
      } catch (e: any) {
        log(e)
        //
      }

      if (externalIp !== undefined) {
        return externalIp
      }
    }

    throw new Error('Could not lookup external IP')
  }

  async stop (options?: AbortOptions): Promise<void> {
    log('Client#close()')

    this.queue = []
    this.connecting = false
    this.listening = false
    this.req = null
    this.reqActive = false

    // TODO
    // await Promise.all([...this.refreshIntervals.entries()].map(async ([port, timeout]) => {
    //   clearTimeout(timeout)
    //   const opts = {
    //     clientAddress: '', // TODO
    //     ...options
    //   }
    //   await this.unmap(port, opts)
    // }))

    this.refreshIntervals.clear()

    if (this.socket != null) {
      this.socket.close()
    }
  }

  private _newMappingNonce (internalHost: string, internalPort: number, protocol: Protocol): MappingNonce {
    return {
      protocol,
      internalHost,
      internalPort,
      nonce: randomBytes(12)
    }
  }

  private getMappingNonce (internalHost: string, internalPort: number, protocol: Protocol): MappingNonce | undefined {
    for (const mn of this.mappingNonces) {
      if (
        mn.internalHost === internalHost &&
        mn.internalPort === internalPort &&
        mn.protocol.toLowerCase() === protocol.toLowerCase()
      ) {
        return mn
      }
    }

    return undefined
  }

  private getOrCreateMappingNonce (internalHost: string, internalPort: number, protocol: Protocol): MappingNonce {
    let mn = this.getMappingNonce(internalHost, internalPort, protocol)
    if (mn === undefined) {
      mn = this._newMappingNonce(internalHost, internalPort, protocol)
      this.mappingNonces.push(mn)
    }

    return mn
  }

  private updateMappingNonce (internalPort: number, protocol: Protocol, nonce: Buffer, externalHost: string, externalPort: number, expiresAt: number): boolean {
    let updated = false

    for (let i = 0; i < this.mappingNonces.length; i++) {
      if (this.mappingNonces[i].internalPort === internalPort &&
        this.mappingNonces[i].protocol.toString().toLowerCase() === protocol.toString().toLowerCase() &&
        (Buffer.compare(this.mappingNonces[i].nonce, nonce) === 0)
      ) {
        this.mappingNonces[i].externalHost = externalHost
        this.mappingNonces[i].externalPort = externalPort
        this.mappingNonces[i].expiresAt = expiresAt
        updated = true
      }
    }

    return updated
  }

  private deleteMappingNonce (internalHost: string, internalPort: number, protocol: Protocol): void {
    this.mappingNonces = this.mappingNonces.filter(mn => {
      return !(
        mn.internalHost === internalHost &&
        mn.internalPort === internalPort &&
        mn.protocol.toLowerCase() === protocol.toLowerCase()
      )
    })
  }

  private pcpRequestHeader (clientIP: string, ttl: number, opcode: number): Buffer {
    // PCP request header layout (24 bytes total):
    //  Byte [0]:    Version (8 bits)
    //  Byte [1]:    Reserved(1 bit) + Opcode(7 bits)
    //  Bytes [2..3]: Reserved (16 bits)
    //  Bytes [4..7]: Lifetime (32 bits)
    //  Bytes [8..23]: Client IP (128 bits, 16 bytes)

    const size = 24
    let pos = 0

    const buf = Buffer.alloc(size)
    buf.writeUInt8(PCP_VERSION, pos)
    pos++

    buf.writeUInt8(((RESERVED_BIT << 7) | (opcode & 0x7F)) & 0xFF, pos)
    pos++

    buf.writeUInt16BE(0, pos) // reserved
    pos += 2

    buf.writeUInt32BE(ttl, pos) // lifetime
    pos += 4

    const ipBuf = to16ByteIP(clientIP)
    ipBuf.copy(buf, pos, 0, 16)

    return buf
  }

  /**
   * Queues a UDP request to be sent to the gateway device.
   */
  request (op: typeof OP_MAP, deferred: DeferredPromise<any>, localPort: number, obj: PCPMapPortOptions): void {
    log('Client#request()', [op, obj])

    let buf
    let size
    let pos = 0
    let ttl

    switch (op) {
      case OP_MAP: {
        if (obj == null) {
          throw new Error('mapping a port requires an "options" object')
        }

        if (obj.protocol === undefined || obj.protocol === null) {
          throw new Error('protocol required')
        }

        ttl = Number(obj.ttl ?? this.options.ttl ?? 0)
        if (ttl !== (ttl | 0)) {
          // Set the Port Mapping Lifetime to the minimum of 120 seconds
          ttl = 120
        }

        // PCP MAP request layout
        //  0-11: Mapping nonce (12 byte)
        //  12: Protocol (1 byte)
        //  13-15: Reserved (3 byte)
        //  16-17: Internal Port (2 byte)
        //  18-19: Suggested External Port (2 byte)
        //  20-35: Suggested External IP (16 byte)
        // Total: 36 bytes.

        size = 24 + 36 // PCP header + MAP op

        buf = Buffer.alloc(size)

        const header = this.pcpRequestHeader(obj.clientAddress, ttl, OP_MAP)

        header.copy(buf, pos, 0, 24)
        pos = 24

        // Mapping nonce
        const mappingNonce = this.getOrCreateMappingNonce(obj.clientAddress, localPort, obj.protocol)
        mappingNonce.nonce.copy(buf, pos, 0, 12)
        pos += 12

        // Protocol
        if (obj.protocol === 'udp' || obj.protocol === 'UDP') {
          buf.writeUInt8(PROTO_UDP, pos)
        } else if (obj.protocol === 'tcp' || obj.protocol === 'TCP') {
          buf.writeUInt8(PROTO_TCP, pos)
        } else {
          throw new Error('unsupported protocol')
        }
        pos++

        // Reserved
        buf.writeUInt8(op, pos)
        buf.writeUInt16BE(0, pos)
        pos += 3

        // Internal Port
        buf.writeUInt16BE(localPort, pos)
        pos += 2

        // Suggested External Port
        buf.writeUInt16BE(obj.suggestedExternalPort ?? localPort, pos)
        pos += 2

        // Suggested external IP
        let suggestedIP: Buffer

        if (obj.suggestedExternalAddress !== undefined && obj.suggestedExternalAddress !== null) {
          suggestedIP = to16ByteIP(obj.suggestedExternalAddress)
        } else {
          if (isIPv4(obj.clientAddress)) {
            suggestedIP = to16ByteIP(EMPTY_IPV4)
          } else {
            suggestedIP = to16ByteIP(EMPTY_IPV6)
          }
        }

        suggestedIP.copy(buf, pos, 0, 16)
        break
      }
      default:
        throw new Error(`Invalid opcode: ${op}`)
    }

    // Add it to queue
    this.queue.push({ op, buf, deferred })

    // Try to send next message
    this._next()
  }

  /**
   * Processes the next request if the socket is listening.
   */
  _next (): void {
    log('Client#_next()')

    const req = this.queue[0]

    if (req == null) {
      log('_next: nothing to process')
      return
    }

    if (this.socket == null) {
      log('_next: client is closed')
      return
    }

    if (!this.listening) {
      log('_next: not "listening" yet, cannot send out request yet')

      if (!this.connecting) {
        this.connect()
      }

      return
    }

    if (this.reqActive) {
      log('_next: already an active request so wait...')
      return
    }

    this.reqActive = true
    this.req = req

    const buf = req.buf

    log('_next: sending request', buf, this.host)
    this.socket.send(buf, 0, buf.length, SERVER_PORT, this.host)
  }

  onListening (): void {
    log('Client#onListening()')
    this.listening = true
    this.connecting = false

    // Try to send next message
    this._next()
  }

  onMessage (msg: Buffer, rinfo: RemoteInfo): void {
    // Ignore message if we're not expecting it
    if (this.queue.length === 0) {
      return
    }

    log('Client#onMessage()', [msg, rinfo])

    const cb = (err?: Error, parsed?: any): void => {
      this.req = null
      this.reqActive = false

      if (err != null) {
        if (req.deferred != null) {
          req.deferred.reject(err)
        } else {
          this.emit('error', err)
        }
      } else if (req.deferred != null) {
        req.deferred.resolve(parsed)
      }

      // Try to send next message
      this._next()
    }

    const req = this.queue[0]
    const parsed: any = { msg }
    parsed.vers = msg.readUInt8(0)

    parsed.r = (msg.readUint8(1) >> 7) & 0x01
    if (parsed.r !== 1) {
      cb(new Error(`"R" must be 1. Got: ${parsed.r}`)) // eslint-disable-line @typescript-eslint/restrict-template-expressions
      return
    }

    parsed.op = msg.readUint8(1) & 0x7F

    if (parsed.op !== req.op) {
      log('WARN: ignoring unexpected message opcode', parsed.op)
      return
    }

    // if we got here, then we're gonna invoke the request's callback,
    // so shift this request off of the queue.
    log('removing "req" off of the queue')
    this.queue.shift()

    if (parsed.vers !== PCP_VERSION) {
      cb(new Error(`"vers" must be ${PCP_VERSION}. Got: ${parsed.vers}`)) // eslint-disable-line @typescript-eslint/restrict-template-expressions
      return
    }

    // Common fields
    parsed.resultCode = msg.readUInt8(3)
    // TODO check resultCode exists
    parsed.resultMessage = RESULT_CODES[parsed.resultCode]

    // Error
    if (parsed.resultCode !== 0) {
      cb(errCode(new Error(parsed.resultMessage), parsed.resultCode))
      return
    }

    parsed.lifetime = msg.readUInt32BE(4)
    if (parsed.lifetime > 24 * 60 * 60) {
      log(`WARN: PCP server allocated a ${parsed.lifetime}s lifetime which is larger than recommended, setting internally to 1 hour`)
      parsed.lifetime = 1 * 60 * 60
    }
    parsed.epoch = msg.readUInt32BE(8)

    // Success
    switch (req.op) {
      case OP_MAP: {
        parsed.nonce = Buffer.alloc(12, 0)
        msg.copy(parsed.nonce, 0, 24, 36) // TODO check nonce match

        const protocol = msg.readUint8(36)
        if (protocol === PROTO_TCP) {
          parsed.protocol = 'TCP'
        } else if (protocol === PROTO_UDP) {
          parsed.protocol = 'UDP'
        } else {
          cb(new Error(`Unsupported protocol: ${parsed.protocol}`))
          return
        }

        parsed.internalPort = msg.readUInt16BE(40)
        parsed.externalPort = msg.readUInt16BE(42)

        parsed.externalAddress = Buffer.alloc(16, 0)
        msg.copy(parsed.externalAddress, 0, 44, 60)

        const updated = this.updateMappingNonce(parsed.internalPort, parsed.protocol, parsed.nonce, parsed.externalAddress, parsed.externalPort, (Math.floor(Date.now() / 1000) + parsed.lifetime) * 1000)
        if (!updated) {
          cb(new Error(`Could not find mapping for ${parsed.internalPort}, ${parsed.type}, ${parsed.nonce.toString('hex')}`))
          return
        }

        log('parsed', parsed)
        break
      }
      default: {
        cb(new Error(`Unknown opcode: ${req.op}`))
        return
      }
    }

    cb(undefined, parsed)
  }

  onClose (): void {
    log('Client#onClose()')
    this.listening = false
    this.connecting = false
  }

  onError (err: Error): void {
    log('Client#onError()', [err])
    if (this.req?.cb != null) {
      this.req.cb(err)
    } else {
      this.emit('error', err)
    }

    if (this.socket != null) {
      this.socket.close()
      // Force close - close() does not guarantee to trigger onClose()
      this.onClose()
    }
  }

  public getMappings (): MappingNonces {
    return this.mappingNonces
  }
}
