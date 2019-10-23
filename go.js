const frida = require('frida')

const fs = require('fs').promises
const path = require('path')
const os = require('os')

class Blob {
  session = ''
  index = 0
  size = 0
  reveiced = 0
  storage = []

  constructor(session, size) {
    this.session = session
    this.size = size
  }
}

class File {
  session = ''
  index = 0
  size = 0
  reveiced = 0
  name = ''
  fd = null

  constructor(session, size, fd) {
    this.session = session
    this.size = size
    this.fd = fd
  }
}

class Handler {
  constructor() {
    this.script = null
    this.blobs = new Map()
    this.files = new Map()
    this.cwd = null
    this.session = null
  }
  
  blob(id) {
    const blob = this.blobs.get(id)
    if (!blob) {
      // console.log('id', id, this.blobs)
      throw new Error('invalid session id')
    }
    return blob
  }

  file(id) {
    const fd = this.files.get(id)
    if (!fd) {
      throw new Error('invalid file id')
    }
    return fd
  }

  async memcpy({ event, session, size, index }, data) {
    if (event === 'begin') {
      const blob = new Blob(session, size)
      this.blobs.set(session, blob)
      this.ack()
    } else if (event === 'data') {
      const blob = this.blob(session)
      if (index != blob.index + 1)
        throw new Error('invalid index')
      blob.size += data.length
      blob.storage.push(data)
      this.ack()
    } else if (event === 'end') {
      
    } else {
      throw new Error('NOTREACHED')
    }
  }

  async patch({ offset, blob, size, filename }) {
    const fd = await fs.open(path.basename(filename), 'a')
    let buf = null
    if (blob) {
      buf = Buffer.concat(this.blob(blob).storage)
      this.blobs.delete(blob)
    } else if (size) {
      buf = Buffer.alloc(size)
      buf.fill(0)
    } else {
      throw new Error('NOTREACHED')
    }

    await fd.write(buf, 0, buf.length, offset)
    await fd.close()
  }

  ack() {
    this.script.post({ type: 'ack' })
  }

  async download({ event, session, stat, size, filename }, data) {
    // this.cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'saltedfish-'))
    if (event === 'begin') {
      const name = path.basename(filename)
      const fd = await fs.open(name, 'w', stat.mode)
      const file = new File(session, size, fd)
      this.files.set(session, file)
      await fs.utimes(name, stat.atimeMs, stat.mtimeMs)
      this.ack()
    } else if (event === 'data') {
      const file = this.file(session)
      await file.fd.write(data)
      this.ack()
    } else if (event === 'end') {
      const file = this.file(session)
      file.fd.close()
      this.files.delete(session)
    } else {
      throw new Error('NOTREACHED')
    }
  }

  connect(script) {
    this.script = script
    script.message.connect(this.dispatcher.bind(this))
  }

  dispatcher({ type, payload }, data) {
    if (type === 'send') {
      const { subject } = payload;
      if (typeof this[subject] === 'function') {
        // don't wait
        // console.log(subject)
        this[subject].call(this, payload, data)
      }
    } else if (type === 'error') {
      session.detach()
    } else {
      console.log('UNKNOWN', type, payload, data)
    }
  }
}

async function main(target) {
  const dev = await frida.getUsbDevice()
  const session = await dev.attach(target)

  const read = (...args) => fs.readFile(path.join(...args)).then(buf => buf.toString())

  const js = await read('dist', 'agent.js')
  const c = await read('cmod', 'source.c')

  const script = await session.createScript(js)
  const handler = new Handler()
  handler.connect(script)

  await script.load()
  await script.exports.prepare(c)

  // get env from main app
  const env = await script.exports.environ();
  console.log(env);
  const plugins = await script.exports.plugins()
  console.log(plugins);

  const pkdSession = await dev.attach('pkd')
  const pkdScript = await pkdSession.createScript(js)
  await pkdScript.load();

  for (let plugin of plugins) {
    console.log('+', await pkdScript.exports.launch(session.pid, plugin.executable, env));
  }

  // const status = await script.exports.dump()
  // console.log(status)
  await script.unload()
  await session.detach()

  await pkdScript.unload()
  await pkdSession.detach()
}

main('WordPress').catch(e => {
  console.error(e)
})