#!/usr/bin/env node

const progress = require('cli-progress')
const chalk = require('chalk')

const fs = require('fs').promises
const path = require('path')

const OUTPUT = 'dump'

const BAR_OPTS = {
  format: chalk.cyan('{bar}') + 
    chalk.grey(' | {percentage}% | {received}/{size}'),
  barCompleteChar: '\u2588',
  barIncompleteChar: '\u2591',
}

function toBarPayload(obj) {
  const result = {}
  for (let key of ['received', 'size']) {
    result[key] = (obj[key] / 1024 / 1024).toFixed(2) + 'Mib'
  }
  return result
}

class Blob {
  session = ''
  index = 0
  size = 0
  received = 0
  storage = []

  constructor(session, size) {
    this.session = session
    this.size = size

    this.bar = new progress.SingleBar(BAR_OPTS)
    this.bar.start(size, 0)
  }

  feed(index, data) {
    if (index != this.index + 1)
        throw new Error(`invalid index ${index}, expected ${blob.index + 1}`)

    this.received += data.length
    this.storage.push(data)
    this.index++
    this.bar.update(this.received, toBarPayload(this))
  }

  done() {
    this.bar.stop()
    return Buffer.concat(this.storage)
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
    this.bar = new progress.SingleBar(BAR_OPTS)
    this.bar.start(size, 0)
  }

  progress(length) {
    this.received += length
    this.bar.update(this.received, toBarPayload(this))
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
      console.log(chalk.green('fetching decrypted data'))

      const blob = new Blob(session, size)
      this.blobs.set(session, blob)
      this.ack()
    } else if (event === 'data') {
      const blob = this.blob(session)
      blob.feed(index, data)
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
      buf = this.blob(blob).done()
      this.blobs.delete(blob)
      console.log()
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

  async download({ event, session, stat, filename, relative }, data) {
    if (event === 'begin') {
      console.log(chalk.bold('download'), chalk.greenBright(relative))
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
      console.log()
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

  console.error(chalk.red('FATAL ERROR: session detached'))
  console.error('reason:', chalk.yellow(reason))
  if (reason === 'server-terminated')
    return

  for (let [key, val] of Object.entries(crash)) {
    console.log(`${key}:`, typeof val === 'string' ? chalk.redBright(val) : val)
  }
}

async function dump(dev, session) {
  try {
    await fs.mkdir(OUTPUT)
  } catch(ex) {
    if (ex.code !== 'EEXIST')
      throw ex
  }

  session.detached.connect(detached)

  const read = (...args) => fs.readFile(path.join(...args)).then(buf => buf.toString())

  const js = await read('dist', 'agent.js')
  const c = await read('cmod', 'source.c')

  const script = await session.createScript(js)
  const handler = new Handler()
  handler.connect(script)

  console.log('dump main app')
  await script.load()
  await script.exports.prepare(c)
  await script.exports.dump()

  console.log('patch PluginKid validation')
  const pkdSession = await dev.attach('pkd')
  const pkdScript = await pkdSession.createScript(js)
  await pkdScript.load()
  await pkdScript.exports.skipPkdValidationFor(session.pid)
  pkdSession.detached.connect(detached)

  try {
    console.log('dump extensions')
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
    console.warn(chalk.redBright(`unable to dump plugins ${ex}`))
  }

  await script.unload()
  await session.detach()

  await pkdScript.unload()
  await pkdSession.detach()
}


const Device = require('./lib/device')
const { getopt } = require('./lib/opts')

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms))


async function main() {
  const opt = getopt()
  const dev = await Device.usb()
  const session = await dev.run(opt.app)
  const { pid } = session
  await dump(dev.dev, session)

  await session.detach()
  await dev.dev.kill(pid)

  // const list = await dev.dev.enumerateApplications()
  // for (let app of list) {
  //   delete app.smallIcon
  //   delete app.largeIcon
  // }
  // console.table(list)
}


main().catch(e => {
  console.error(chalk.red('FATAL ERROR'))
  console.error(chalk.red(e))
  process.exit()
})