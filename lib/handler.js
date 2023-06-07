import frida from 'frida'

export default class Handler {
  /**
   * @param {string} cwd working directory
   * @param {string} root bundle root
   */
  constructor(cwd, root) {
    this.cwd = cwd
    this.root = root

    /** @type {frida.Script | null} */
    this.script = null
    
    /** @type {frida.Session | null} */
    this.session = null
  }

  /**
   * @param {frida.Script} script
   */
  connect(script) {
    script.on('message', ({ type, payload }, data) => {
      if (type === 'send') {
        // todo:
      }
    })
    this.script = script
  }
}