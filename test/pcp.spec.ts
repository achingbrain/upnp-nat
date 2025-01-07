import { expect } from 'aegir/chai'
import { pcp } from '../src/index.js'
import { randomPort } from './fixtures/random-port.js'
import type { Gateway } from '../src/index.js'
import type { PCPGateway } from '../src/pcp/gateway.js'

// Helper to wait until at least one mapping has expiresAt > 2 minutes from now
async function waitForRefreshedMapping (
  gateway: PCPGateway,
  maxWaitMs: number // total time to poll before giving up
): Promise<boolean> {
  const start = Date.now()
  const initialMappings = JSON.parse(JSON.stringify(gateway.getMappings()))
  // const initialMappings = gateway.getMappings()

  while ((Date.now() - start) < maxWaitMs) {
    const mappings = gateway.getMappings()
    // console.log({ mappings })

    // Look for any mapping with expiresAt > 2 minutes from now
    for (const initial of initialMappings) {
      for (const current of mappings) {
        const initialExpiresAt = initial.expiresAt
        const currentExpiresAt = current.expiresAt

        // Ensure expiresAt values are defined
        if (initialExpiresAt !== undefined && currentExpiresAt !== undefined) {
          // Check if mapping matches and has been refreshed
          if (initial.internalHost === current.internalHost &&
              initial.internalPort === current.internalPort &&
              initial.protocol === current.protocol &&
              initialExpiresAt < currentExpiresAt) {
            return true // Found a refreshed mapping
          } else {
            // console.log(`Initial: ${initialExpiresAt}, Current: ${currentExpiresAt}`)
          }
        }
      }
    }

    // Wait for 5 seconds before polling again
    await new Promise(resolve => setTimeout(resolve, 5000))
  }

  // Timeout exceeded, no refreshed mapping found
  return false
}

describe('pcp-nat-port-mapper', () => {
  let gateway: Gateway

  afterEach(async () => {
    await gateway?.stop()
  })

  it('should map a port', async () => {
    if (process.env.CI != null) {
      return // CI environments don't have PCP routers!
    }

    if (process.env.GATEWAY === undefined) {
      throw new Error('GATEWAY env not set')
    }

    const port = randomPort()
    const mapped = []

    gateway = pcp(process.env.GATEWAY)

    for await (const mapping of gateway.mapAll(port, {})) {
      // console.log('mapping', mapping)
      expect(mapping.externalHost).to.be.a('string')
      expect(mapping.externalPort).to.be.a('number')

      expect(mapping.internalHost).to.be.a('string')
      expect(mapping.internalPort).to.be.a('number')

      mapped.push(mapping)
    }

    // Ensure that we got at least one successful mapping
    expect(mapped).to.have.lengthOf.at.least(1)

    await new Promise<void>((resolve) => {
      setTimeout(() => {
        resolve()
      }, 5000)
    })

    // await gateway.unmap(port) // TODO
  })

  it('should refresh a mapping', async () => {
    if (process.env.CI != null) {
      return // CI environments don't have PCP routers!
    }

    if (process.env.GATEWAY === undefined) {
      throw new Error('GATEWAY env not set')
    }

    const port = randomPort()
    const mapped = []

    gateway = pcp(process.env.GATEWAY)

    const ttl = 120
    for await (const mapping of gateway.mapAll(port, { ttl })) {
      // console.log('mapping', mapping)
      expect(mapping.externalHost).to.be.a('string')
      expect(mapping.externalPort).to.be.a('number')

      expect(mapping.internalHost).to.be.a('string')
      expect(mapping.internalPort).to.be.a('number')

      mapped.push(mapping)
    }

    // Ensure that we got at least one successful mapping
    expect(mapped).to.have.lengthOf.at.least(1)

    const maxWaitMs = 2.5 * 60 * 1000
    expect(await waitForRefreshedMapping(gateway as PCPGateway, maxWaitMs)).to.eq(true)

    // await gateway.unmap(port) // TODO
  }).timeout(3 * 60 * 1000)

  it('should discover an external ip address', async () => {
    if (process.env.CI != null) {
      return // CI environments don't have NAT-PMP routers!
    }

    if (process.env.GATEWAY === undefined) {
      throw new Error('GATEWAY env not set')
    }

    gateway = pcp(process.env.GATEWAY)

    const ip = await gateway.externalIp({
      signal: AbortSignal.timeout(5000)
    })

    expect(ip).to.be.ok()
  })
})
