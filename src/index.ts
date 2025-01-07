/**
 * @packageDocumentation
 *
 * Enable NAT traversal by mapping public ports to ports on your computer using
 * either [UPnP](https://en.wikipedia.org/wiki/Universal_Plug_and_Play) or
 * [NAT-PMP](https://en.wikipedia.org/wiki/NAT_Port_Mapping_Protocol).
 *
 * @example UPnP NAT
 *
 * ```TypeScript
 * import { upnpNat } from '@achingbrain/nat-port-mapper'
 *
 * const client = upnpNat()
 *
 * for await (const gateway of client.findGateways({ signal: AbortSignal.timeout(10000) })) {
 *   // Map public port 1000 to private port 1000 with TCP
 *   await gateway.map(1000, '192.168.1.123', {
 *     protocol: 'tcp'
 *   })
 *
 *   // Map port 3000 to any available host name
 *   for await (const mapping of gateway.mapAll(3000, {
 *     protocol: 'udp'
 *   })) {
 *     console.info(`mapped ${mapping.internalHost}:${mapping.internalPort} to ${mapping.externalHost}:${mapping.externalPort}`)
 *   }
 *
 *   // Unmap previously mapped private port 1000
 *   await gateway.unmap(1000)
 *
 *   // Get external IP
 *   const externalIp = await gateway.externalIp()
 *
 *   console.log('External IP:', externalIp)
 *
 *   // Unmap all mapped ports and cancel any in-flight network operations
 *   await gateway.stop()
 * }
 * ```
 *
 * @example NAT-PMP
 *
 * ```TypeScript
 * import { pmpNat } from '@achingbrain/nat-port-mapper'
 * import { gateway4sync } from 'default-gateway'
 *
 * const gateway = pmpNat(gateway4sync().gateway)
 *
 * // Map public port 1000 to private port 1000 with TCP
 * await gateway.map(1000, '192.168.1.123', {
 *   protocol: 'tcp'
 * })
 *
 * // Map public port 2000 to private port 3000 with UDP
 * await gateway.map(3000, '192.168.1.123', {
 *   externalPort: 2000,
 *   protocol: 'udp'
 * })
 *
 * // Unmap previously mapped private port 1000
 * await gateway.unmap(1000)
 *
 * // Get external IP
 * const externalIp = await gateway.externalIp()
 *
 * console.log('External IP:', externalIp)
 *
 * // Unmap all mapped ports and cancel any in-flight network operations
 * await gateway.stop()
 * ```
 *
 * ## Credits
 *
 * Based on [alxhotel/nat-api](https://github.com/alxhotel/nat-api)
 *
 * ## Additional Information
 *
 * - <http://miniupnp.free.fr/nat-pmp.html>
 * - <http://wikipedia.org/wiki/NAT_Port_Mapping_Protocol>
 * - <http://tools.ietf.org/html/draft-cheshire-nat-pmp-03>
 */

import { PCPGateway } from './pcp/gateway.js'
import { PMPGateway } from './pmp/gateway.js'
import { UPnPClient } from './upnp/index.js'
import type { AbortOptions } from 'abort-error'

export type Protocol = 'tcp' | 'TCP' | 'udp' | 'UDP'

export interface GlobalMapPortOptions {
  /**
   * TTL for port mappings in ms
   *
   * @default 3_600_000
   */
  ttl?: number

  /**
   * If passed this will be used as the default description when mapping ports
   *
   * @default '@achingbrain/nat-port-mapper'
   */
  description?: string

  /**
   * If true, any mapped ports will be refreshed when their lease expires
   *
   * @default true
   */
  autoRefresh?: boolean

  /**
   * How long to wait while trying to refresh a port mapping in ms
   *
   * @default 10_000
   */
  refreshTimeout?: number

  /**
   * How long before expiry to remap the port mapping in ms
   *
   * @default 60_000
   */
  refreshThreshold?: number
}

export interface MapPortOptions extends GlobalMapPortOptions, AbortOptions {
  /**
   * The external port to map. If omitted a free port will be chosen.
   *
   * @default localPort
   */
  externalPort?: number

  /**
   * If specified, only packets from this host will be accepted by the gateway.
   *
   * An empty string specifies any host.
   *
   * @default ''
   */
  remoteHost?: string

  /**
   * The protocol the port uses
   *
   * @default 'TCP'
   */
  protocol?: Protocol
}

export interface PCPMapPortOptions extends GlobalMapPortOptions, AbortOptions {
  clientAddress: string

  /**
   * The suggested external port to map - best effort as may already be mapped on the PCP server to a different client
   *
   * @default localPort
   */
  suggestedExternalPort?: number

  /**
   * The suggested external ip address to map - best effort as the address may not be available on the PCP server
   *
   * @default ''
   */
  suggestedExternalAddress?: string

  /**
   * The protocol the port uses
   *
   * @default 'TCP'
   */
  protocol?: Protocol
}

export interface PortMapping {
  /**
   * The host that remote hosts can use to send packets to the mapped port
   */
  externalHost: string

  /**
   * The port that remote hosts can send packets to
   */
  externalPort: number

  /**
   * The internal host that will receive packets
   */
  internalHost: string

  /**
   * The internal port that will receive packets
   */
  internalPort: number

  /**
   * The protocol that was mapped
   */
  protocol: 'TCP' | 'UDP'
}

export interface Gateway {
  /**
   * A unique identifier for this gateway
   */
  id: string

  /**
   * The network host that this gateway is accessible on
   */
  host: string

  /**
   * The port that this gateway uses
   */
  port: number

  /**
   * If `IPv4`, this gateway is capable of mapping IPv4 addresses, otherwise it
   * will map IPv6 addresses
   */
  family: 'IPv4' | 'IPv6'

  /**
   * Stop all network transactions and unmap any mapped ports
   */
  stop(options?: AbortOptions): Promise<void>

  /**
   * Map a local host:port pair to one on the external network interface
   *
   * If the mapping is successful, the external port number that was mapped is
   * returned - this may be different from the requested port number if that
   * port was not free.
   */
  map(internalPort: number, internalHost: string, options?: MapPortOptions): Promise<PortMapping>

  /**
   * Try mapping the passed port using all eligible network interfaces on the
   * current machine.
   *
   * Yields successful host:port pairs and will throw if no successful mapping
   * occurs.
   */
  mapAll(internalPort: number, options?: MapPortOptions): AsyncGenerator<PortMapping, void, unknown>

  /**
   * Unmap a previously mapped port. If the port was not mapped this is a no-op.
   */
  unmap(internalPort: number, options?: AbortOptions): Promise<void>

  /**
   * Find the external network IP address, usually an IPv4 class address.
   */
  externalIp(options?: AbortOptions): Promise<string>
}

export interface FindGatewaysOptions extends AbortOptions {
  /**
   * How often to broadcast `SSDP M-SEARCH` messages while finding gateways.
   *
   * By default it is done once at the beginning of the search, pass a ms value
   * here to broadcast it on an interval.
   *
   * This may be necessary if devices on your network do not always respond to
   * search messages.
   */
  searchInterval?: number
}

export interface UPnPNATOptions extends GlobalMapPortOptions {
  /**
   * When a discovered gateway's TTL expires we will attempt to relocate it on
   * the local network.  By default only one `SSDP M-SEARCH` message will be
   * broadcast at the beginning of the search, pass a ms value here to instead
   * broadcast it on an interval.
   *
   * This may be necessary if devices on your network do not always respond to
   * search messages.
   */
  gatewaySearchInterval?: number
}

export interface UPnPNAT {
  /**
   * Search the local network for gateways - when enough gateways have been
   * found, either break out of the `for await..of` loop or abort a passed
   * `AbortSignal`.
   */
  findGateways (options?: FindGatewaysOptions): AsyncGenerator<Gateway, void, unknown>

  /**
   * Use a specific network gateway for port mapping.
   *
   * For UPnP this should be a fully qualified URL to a device descriptor XML
   * document, e.g. `http://192.168.1.1:4558/rootDesc.xml`
   */
  getGateway (descriptor: URL, options?: AbortOptions): Promise<Gateway>
}

/**
 * Create a UPnP port mapper
 */
export function upnpNat (options: UPnPNATOptions = {}): UPnPNAT {
  return new UPnPClient(options)
}

export interface PMPNAT {
  /**
   * Use a specific network gateway for port mapping
   */
  getGateway (ipAddress: string, options?: AbortOptions): Gateway
}

/**
 * Create a NAT-PMP port mapper
 */
export function pmpNat (ipAddress: string, options: GlobalMapPortOptions = {}): Gateway {
  return new PMPGateway(ipAddress, options)
}

/**
 * Create a PCP port mapper
 */
export function pcp (ipAddress: string, options: GlobalMapPortOptions = {}): Gateway {
  return new PCPGateway(ipAddress, options)
}
