import { randomBytes } from 'crypto'
import { createSocket } from 'dgram'
import { EventEmitter } from 'events'
import { isIPv4, isIPv6 } from '@chainsafe/is-ip'
import { logger } from '@libp2p/logger'
import errCode from 'err-code'
import defer, { type DeferredPromise } from 'p-defer'
import { raceSignal } from 'race-signal'
import { DEFAULT_PORT_MAPPING_TTL, DEFAULT_REFRESH_THRESHOLD, DEFAULT_REFRESH_TIMEOUT } from '../upnp/constants.js'
import { findLocalAddresses } from '../upnp/utils.js'
import { isPrivateIp, to16ByteIP } from '../utils.js'
import type { Gateway, MapPortOptions, GlobalMapPortOptions, PortMapping, PCPMapPortOptions } from '../index.js'
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
// const SERVER_DELTA = 128

// Bits
const RESERVED_BIT = 0

// Protocols
const PROTO_TCP = 0x06
const PROTO_UDP = 0x11

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
  12: 'Address mismatch (source address does not match requested PCP client address)', // possibly sent using wrong IP address or there is a NAT between the client and server
  13: 'Excessive remote peers'
}

export interface PortMappingOptions {
  type?: 'tcp' | 'udp'
  ttl?: number
  public?: number
  private?: number
  internal?: number
  external?: number
}

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
    this.socket.bind(CLIENT_PORT)
  }

  async * mapAll (localPort: number, options: PCPMapPortOptions): AsyncGenerator<PortMapping, void, unknown> {
    let mapped = false

    for (const host of findLocalAddresses(this.family)) {
      try {
        console.log('host', host)
        options.clientAddress = host
        const mapping = await this.map(localPort, host, options)
        mapped = true

        yield mapping
      } catch (err) {
        log.error('error mapping %s:%d - %e', host, localPort, err)
      }
    }

    if (!mapped) {
      throw new Error(`All attempts to map port ${localPort} failed`)
    }
  }

  async map (localPort: number, localHost: string, opts: PCPMapPortOptions): Promise<PortMapping> {
    console.log('in map')
    const options = {
      clientAddress: opts.clientAddress,
      publicPort: opts?.suggestedExternalPort ?? localPort,
      publicHost: opts?.suggestedExternalAddress ?? '',
      localAddress: localHost,
      protocol: opts?.protocol ?? 'tcp',
      description: opts?.description ?? this.options.description ?? '@achingbrain/nat-port-mapper',
      ttl: opts?.ttl ?? this.options.ttl ?? DEFAULT_PORT_MAPPING_TTL,
      autoRefresh: opts?.autoRefresh ?? this.options.autoRefresh ?? true,
      refreshTimeout: opts?.refreshTimeout ?? this.options.refreshTimeout ?? DEFAULT_REFRESH_TIMEOUT,
      refreshBeforeExpiry: opts?.refreshThreshold ?? this.options.refreshThreshold ?? DEFAULT_REFRESH_THRESHOLD
    }
    console.log('x1', opts)

    log('Client#portMapping()')
    switch (options.protocol.toLowerCase()) {
      case 'tcp':
        break
      case 'udp':
        break
      default:
        throw new Error('"type" must be either "tcp" or "udp"')
    }

    const deferred = defer<{ public: number, private: number, ttl: number, type: 'TCP' | 'UDP' }>()

    this.request(OP_MAP, deferred, localPort, options)

    const result = await raceSignal(deferred.promise, opts?.signal)

    if (options.autoRefresh) {
      const refresh = ((localPort: number, opts: PCPMapPortOptions): void => {
        this.map(localPort, localHost, {
          ...opts,
          signal: AbortSignal.timeout(options.refreshTimeout)
        })
          .catch(err => {
            log.error('could not refresh port mapping - %e', err)
          })
      }).bind(this, localPort, {
        ...options,
        signal: undefined
      })

      this.refreshIntervals.set(localPort, setTimeout(refresh, options.ttl - options.refreshBeforeExpiry))
    }

    return {
      externalHost: isPrivateIp(localHost) === true ? await this.externalIp(opts) : localHost,
      externalPort: result.public,
      internalHost: localHost,
      internalPort: result.private,
      protocol: result.type
    }
  }

  async unmap (localPort: number, opts: PCPMapPortOptions): Promise<void> {
    log('Client#portUnmapping()')

    await this.map(localPort, '', {
      ...opts,
      description: '',
      ttl: 0
    })
  }

  async externalIp (options?: AbortOptions): Promise<string> {
    // TODO create a short lived map to get the external IP as recommeneded by the spec 11.6 Learning the External IP
    // Address Alone. Should be OK for residential NATs but Carrier-Grade NATs may use a pool of addresses so the
    // the external address isn't guaranteed.
    throw new Error('unsupported')
  }

  async stop (options?: AbortOptions): Promise<void> {
    log('Client#close()')

    this.queue = []
    this.connecting = false
    this.listening = false
    this.req = null
    this.reqActive = false

    await Promise.all([...this.refreshIntervals.entries()].map(async ([port, timeout]) => {
      clearTimeout(timeout)
      const opts = {
        clientAddress: '', // TODO
        ...options
      }
      await this.unmap(port, opts)
    }))

    this.refreshIntervals.clear()

    if (this.socket != null) {
      this.socket.close()
    }
  }

  private generateMappingNonce (): Buffer {
    return randomBytes(12)
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
   * Queues a UDP request to be send to the gateway device.
   */
  request (op: typeof OP_MAP, deferred: DeferredPromise<any>, localPort: number, obj: PCPMapPortOptions): void {
    console.log('request')
    log('Client#request()', [op, obj])

    let buf
    let size
    let pos = 0
    let ttl

    switch (op) {
      case OP_MAP:
        if (obj == null) {
          throw new Error('mapping a port requires an "options" object')
        }

        ttl = Number(obj.ttl ?? this.options.ttl ?? 0)
        if (ttl !== (ttl | 0)) {
          // Set the Port Mapping Lifetime to the minimum of 120 seconds
          ttl = 120
        }

        size = 24 + 36 // PCP header + MAP
        buf = Buffer.alloc(size)

        const header = this.pcpRequestHeader(obj.clientAddress, ttl, OP_MAP)

        header.copy(buf, pos, 0, 24)
        pos = 24

        // PCP MAP request layout
        //  0-11: Mapping nonce (12 byte)
        //  12: Protocol (1 byte)
        //  13-15: Reserved (3 byte)
        //  16-17: Internal Port (2 byte)
        //  18-19: Suggested External Port (2 byte)
        //  20-35: Suggested External IP (16 byte)
        // Total: 36 bytes.

        const nonce = this.generateMappingNonce()
        nonce.copy(buf, pos, 0, 12)
        pos += 12

        if (obj.protocol === 'udp' || obj.protocol === 'UDP') {
          buf.writeUInt8(PROTO_UDP, pos)
        } else {
          buf.writeUInt8(PROTO_TCP, pos)
        }
        pos++

        // reserved bytes
        buf.writeUInt8(op, pos)
        buf.writeUInt16BE(0, pos)
        pos += 3

        buf.writeUInt16BE(localPort, pos)
        pos += 2 // Internal Port

        buf.writeUInt16BE(obj.suggestedExternalPort ?? localPort, pos)
        pos += 2 // Suggested External Port

        // TODO suggested external IP

        break
      default:
        throw new Error(`Invalid opcode: ${op}`)
    }
    // assert.equal(pos, size, 'buffer not fully written!')

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
    parsed.op = msg.readUInt8(1)

    // if (parsed.op - SERVER_DELTA !== req.op) {
    //   log('WARN: ignoring unexpected message opcode', parsed.op)
    //   return
    // }

    // if we got here, then we're gonna invoke the request's callback,
    // so shift this request off of the queue.
    log('removing "req" off of the queue')
    this.queue.shift()

    if (parsed.vers !== 0) {
      cb(new Error(`"vers" must be 0. Got: ${parsed.vers}`)) // eslint-disable-line @typescript-eslint/restrict-template-expressions
    }

    // // Common fields
    // parsed.resultCode = msg.readUInt16BE(2)
    // parsed.resultMessage = RESULT_CODES[parsed.resultCode]
    // parsed.epoch = msg.readUInt32BE(4)
    //
    // // Error
    // if (parsed.resultCode !== 0) {
    //   cb(errCode(new Error(parsed.resultMessage), parsed.resultCode)); return
    // }
    //
    // // Success
    // switch (req.op) {
    //   case OP_MAP:
    //     parsed.private = parsed.internal = msg.readUInt16BE(8)
    //     parsed.public = parsed.external = msg.readUInt16BE(10)
    //     parsed.ttl = msg.readUInt32BE(12)
    //     break
    //   default:
    //     { cb(new Error(`Unknown opcode: ${req.op}`)); return }
    // }
    //
    // cb(undefined, parsed)
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
}
