#!/usr/bin/env node

const progress = require('cli-progress')
const chalk = require('chalk')

const fs = require('fs').promises
const path = require('path')
const os = require('os')

const mkdirp = require('./lib/mkdirp')

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
  bar = null
  verbose = false

  constructor(session, size, fd) {
    this.session = session
    this.size = size
    this.fd = fd

    if (size > 4 * 1024 * 1024) {
      this.bar = new progress.SingleBar(BAR_OPTS)
      this.bar.start(size, 0)
      this.verbose = true
    }

  }

  progress(length) {
    this.received += length
    if (this.verbose)
      this.bar.update(this.received, toBarPayload(this))
  }

  done() {
    if (this.verbose)
      this.bar.stop()
    this.fd.close()
  }
}

class Handler {
  /**
   * @param {string} cwd working directory
   * @param {string} root bundle root
   */
  constructor(cwd, root) {
    this.script = null
    this.blobs = new Map()
    this.files = new Map()
    this.root = root
    this.cwd = cwd
    this.session = null
    this.misc = {}
  }

  /**
   * get Blob by uuid
   * @param {string} id uuid
   */
  blob(id) {
    const blob = this.blobs.get(id)
    if (!blob) {
      // console.log('id', id, this.blobs)
      throw new Error('invalid session id')
    }
    return blob
  }

  /**
   * get file object by uuid
   * @param {string} id uuid
   */
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

  /**
   * secure path concatenation
   * @param {string} filename relative path component
   */
  async output(filename) {
    const abs = path.resolve(this.cwd, path.relative(this.root, filename))
    const rel = path.relative(this.cwd, abs)
    if (rel && !rel.startsWith('..') && !path.isAbsolute(rel)) {
      await mkdirp(path.dirname(abs))
      return abs
    }
    throw Error(`Suspicious path detected: ${filename}`)
  }

  async patch({ offset, blob, size, filename }) {
    const output = await this.output(filename)
    const fd = await fs.open(output, 'r+')
    let buf = null
    if (blob) {
      buf = this.blob(blob).done()
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

  truncate(str) {
    const MAX = 80
    const len = str.length - MAX
    return len > 0 ? `...${str.substr(len)}` : str
  }

  async download({ event, session, stat, filename }, data) {
    if (event === 'begin') {
      console.log(chalk.bold('download'), chalk.greenBright(this.truncate(filename)))
      const output = await this.output(filename)
      const fd = await fs.open(output, 'w', stat.mode)
      const file = new File(session, stat.size, fd)
      this.files.set(session, file)
      try {
        await fs.utimes(output, stat.atimeMs, stat.mtimeMs)
      } catch(e) {
        this.misc.warnAboutNTFS = e.code === 'EINVAL' && os.platform() === 'win32'
      }
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
      if (['memcpy', 'download', 'patch'].includes(subject)) {
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

  if (!crash)
    return

  for (let [key, val] of Object.entries(crash))
    console.log(`${key}:`, typeof val === 'string' ? chalk.redBright(val) : val)
}

async function dump(dev, session, opt) {
  const { output } = opt
  await mkdirp(output)
  const parent = path.join(output, opt.app, 'Payload')

  try {
    const stat = await fs.stat(parent)
    if (stat.isDirectory() && !opt.override)
      throw new Error(`Destination ${parent} already exists. Try --override`)
  } catch (ex) {
    if (ex.code !== 'ENOENT')
      throw ex
  }

  session.detached.connect(detached)

  const read = (...args) => fs.readFile(path.join(__dirname, ...args)).then(buf => buf.toString())
  const js = await read('dist', 'agent.js')
  const c = await read('cmod', 'source.c')

  const script = await session.createScript(js)
  await script.load()
  const root = await script.exports.base()
  const cwd = path.join(parent, path.basename(root))
  await mkdirp(cwd)

  console.log('app root:', chalk.green(root))

  const handler = new Handler(cwd, root)
  handler.connect(script)

  console.log('dump main app')

  await script.exports.prepare(c)
  await script.exports.dump(opt)

  console.log('patch PluginKit validation')
  const pkdSession = await dev.attach('pkd')
  const pkdScript = await pkdSession.createScript(js)
  await pkdScript.load()
  await pkdScript.exports.skipPkdValidationFor(session.pid)
  pkdSession.detached.connect(detached)

  try {
    console.log('dump extensions')
    const pids = await script.exports.launchAll()
    for (let pid of pids) {
      if (await pkdScript.exports.jetsam(pid) !== 0) {
        throw new Error(`unable to unchain ${pid}`)
      }

      const pluginSession = await dev.attach(pid)
      const pluginScript = await pluginSession.createScript(js)
      pluginSession.detached.connect(detached)

      await pluginScript.load()
      await pluginScript.exports.prepare(c)
      const childHandler = new Handler(cwd, root)
      childHandler.connect(pluginScript)

      await pluginScript.exports.dump(opt)
      await pluginScript.unload()
      await pluginSession.detach()
      await dev.kill(pid)
    }
  } catch (ex) {
    console.warn(chalk.redBright(`unable to dump plugins ${ex}`))
    console.warn(ex)
  }

  if (handler.misc.warnAboutNTFS) {
    console.warn(chalk.yellow(`WARNING: Failed to update file timestamps. This is probably because you're 
      on Windows and using NTFS, which is incompatible with some file attributes.`))
  }

  await script.unload()
  await session.detach()

  await pkdScript.unload()
  await pkdSession.detach()

  console.log(chalk.green('Congrats!'))
  console.log('open', chalk.greenBright(parent))
}


const Device = require('./lib/device')


async function main() {
  const program = require('commander')

  program
    .name('bagbak')
    .option('-l, --list', 'list apps')
    .option('-H, --host <host>', 'hostname (optional)')
    .option('-u, --uuid <uuid>', 'uuid of USB device (optional)')
    .option('-o, --output <output>', 'output directory', 'dump')
    .option('-f, --override', 'override existing')
    .option('-e, --executable-only', 'dump executables only')
    .option('-z, --zip', 'create zip archive (ipa)')
    .usage('[bundle id or name]')

  program.parse(process.argv)

  if (program.uuid && program.host)
    throw new Error('Use either uuid or host')

  if (program.args.length > 1)
    throw new Error('For stability, only decrypt one app once')

  if (program.list && program.args.length)
    throw new Error('Invalid command')

  let device = null
  if (program.uuid)
    device = await Device.find(program.uuid)
  else if (program.host)
    device = await Device.connect(program.host)
  else
    device = await Device.usb()

  if (program.list) {
    const list = await device.dev.enumerateApplications()
    for (let app of list) {
      delete app.smallIcon
      delete app.largeIcon
    }
    list.sort((a, b) => (a.name.toLowerCase() > b.name.toLowerCase()) ? 1 : -1)
    console.table(list)
    return
  }

  if (program.args.length === 1) {
    const app = program.args[0]
    const opt = Object.assign({ app }, program)
    const session = await device.run(app)
    const { pid } = session
    await dump(device.dev, session, opt)

    await session.detach()
    // await device.dev.kill(pid)

    if (program.zip) {
      console.log('trying to create zip archive')
      const { spawn } = require('child_process')
      const cwd = path.join(program.output, app)
      let child
      try {
        child = spawn('zip', ['-r', `../${app}.ipa`, 'Payload'], { stdio: 'inherit', cwd: cwd })
      } catch (ex) {
        if (ex.errno == 'ENOENT') {
          console.warn('zip command not found in the PATH')
          console.info(`If you need an ipa, pack ${cwd}/Payload in zip archive`)
        }
        throw ex
      }
  
      await new Promise((resolve, reject) =>
        child.on('close', (code) => code === 0 ? resolve() : reject(code)))
      
      console.log(`archive: ${cwd}.ipa`)
      console.log(`contents: ${chalk.green(cwd)}`)
    }

    return
  }

  program.help()
}


main().catch(e => {
  console.error(chalk.red('FATAL ERROR'))
  console.error(e)
  process.exit()
})
