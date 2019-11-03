const frida = require('frida')

class Device {
  static manager = new frida.DeviceManager()
  constructor(dev) {
    this.dev = dev
  }

  /**
   * 
   * @param {string} host
   * @returns {Promise<Device>}
   */
  static async connect(host) {
    const dev = await Action.manager.addRemoteDevice(host)
    return new Device(dev)
  }

  /**
   * @returns {Promise<Device>}
   */
  static async usb() {
    return new Device(await frida.getUsbDevice())
  }

  static async find(partialId) {
    const list = await frida.enumerateDevices()
    for (let dev of list)
      if (dev.id.startsWith(partialId))
        return new Device(dev)

    throw new Error(`Unable to find device that matches id == ${partialId}`)
  }

  /**
   * 
   * @param {string} name bundle id or app name
   * @returns {Promise<frida.Session>}
   */
  async run(name) {
    const apps = await this.dev.enumerateApplications()
    const app = apps.find(app => app.name === name || app.identifier === name)
    if (!app)
      throw new Error(`Unable to find app: ${name}`)

    let needsNew = app.pid === 0

    if (!needsNew) {
      const front = await this.dev.getFrontmostApplication()
      if (front && front.pid !== app.pid) {
        await this.dev.kill(app.pid)
        needsNew = true
      }
    }

    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))

    if (needsNew) {
      const pid = await this.dev.spawn(app.identifier)
      await this.dev.resume(pid)
      await sleep(1000)
      const session = await this.dev.attach(pid)
      return session
    }
  
    return this.dev.attach(app.pid)
  }

}

module.exports = Device
