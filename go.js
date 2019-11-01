const frida = require('frida')
const progress = require('cli-progress')

const fs = require('fs').promises
const path = require('path')

const OUTPUT = 'dump'

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
  received = 0
  name = ''
  fd = null

  constructor(session, size, fd) {
    this.session = session
    this.size = size
    this.fd = fd
    this.bar = new progress.SingleBar({}, progress.Presets.shades_classic)
    this.bar.start(size, 0)
  }

  progress(length) {
    this.received += length
    this.bar.update(this.received)
  }

  done() {
    this.bar.stop()
    this.fd.close()
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
        throw new Error(`invalid index ${index}, expected ${blob.index + 1}`)
      blob.size += data.length
      blob.storage.push(data)
      blob.index++
      this.ack()
    } else if (event === 'end') {
      
    } else {
      throw new Error('NOTREACHED')
    }
  }

  async patch({ offset, blob, size, filename }) {
    const output = path.join('dump', path.basename(filename))
    const fd = await fs.open(output, 'a')
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

  async download({ event, session, stat, filename }, data) {
    // this.cwd = await fs.mkdtemp(path.join(os.tmpdir(), 'saltedfish-'))
    if (event === 'begin') {
      const output = path.join('dump', path.basename(filename))
      const fd = await fs.open(output, 'w', stat.mode)
      const file = new File(session, stat.size, fd)
      this.files.set(session, file)
      await fs.utimes(output, stat.atimeMs, stat.mtimeMs)
      this.ack()
    } else if (event === 'data') {
      const file = this.file(session)
      file.progress(data.length)
      await file.fd.write(data)
      this.ack()
    } else if (event === 'end') {
      const file = this.file(session)
      file.done()
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

function detached(reason, crash) {
  if (reason === 'application-requested')
    return

  console.error('FATAL ERROR: session detached')
  console.error('reason:', reason)
  for (let [key, val] of Object.entries(crash)) {
    console.log(`${key}:`, val)
  }
}

async function main(target) {
  try {
    await fs.mkdir(OUTPUT)
  } catch(ex) {
    if (ex.code !== 'EEXIST')
      throw ex
  }

  const dev = await frida.getUsbDevice()
  const session = await dev.attach(target)
  session.detached.connect(detached)

  const read = (...args) => fs.readFile(path.join(...args)).then(buf => buf.toString())

  const js = await read('dist', 'agent.js')
  const c = await read('cmod', 'source.c')

  const script = await session.createScript(js)
  const handler = new Handler()
  handler.connect(script)

  await script.load()
  await script.exports.prepare(c)
  await script.exports.dump()


  const pkdSession = await dev.attach('pkd')
  const pkdScript = await pkdSession.createScript(js)
  await pkdScript.load()
  await pkdScript.exports.skipPkdValidationFor(session.pid)
  pkdSession.detached.connect(detached)

  try {
    const pids = await script.exports.launchAll()
    for (let pid of pids) {
      const pluginSession = await dev.attach(pid)
      const pluginScript = await pluginSession.createScript(js)  
      pluginSession.detached.connect(detached)

      if (await pkdScript.exports.jetsam(pid) !== 0) {
        throw new Error(`unable to unchain ${pid}`)
      }
  
      await pluginScript.load()
      await pluginScript.exports.prepare(c)
      const childHandler = new Handler()
      childHandler.connect(pluginScript)
  
      await pluginScript.exports.dump()
  
      await pluginScript.unload()
      await pluginSession.detach()
      await dev.kill(pid)
    }
  } catch(ex) {
    console.warn(`unable to dump plugins ${ex}`)
  }

  await script.unload()
  await session.detach()

  await pkdScript.unload()
  await pkdSession.detach()
}

main(process.argv[2]).catch(e => {
  console.error('FATAL ERROR')
  console.error(e)
  process.exit()
})