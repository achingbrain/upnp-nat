import { EventEmitter } from 'events'
import { PCPGateway } from './gateway.js'
import type { Gateway, GlobalMapPortOptions } from '../index.js'

export class PCPClient extends EventEmitter {
  private readonly options: GlobalMapPortOptions

  constructor (options: GlobalMapPortOptions = {}) {
    super()

    this.options = options
  }

  getGateway (ipAddress: string): Gateway {
    return new PCPGateway(ipAddress, this.options)
  }
}
