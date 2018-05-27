import macho from 'macho'

import { open, close, write, lseek, unlink, O_RDONLY, O_RDWR, SEEK_SET } from './libc'
import ReadOnlyMemoryBuffer from './romembuf'
import { NSTemporaryDirectory, getFileInfo } from './foundation'


function dump(module) {
  const { name } = module
  const buffer = new ReadOnlyMemoryBuffer(module.base, module.size)
  const info = macho.parse(buffer)
  const matches = info.cmds.filter(cmd => /^encryption_info(_64)?$/.test(cmd.type) && cmd.id === 1)
  if (!matches.length) {
    console.warn(`Module ${name} is not encrypted`)
    return null
  }

  const encryptionInfo = matches.pop()
  const fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0)
  if (fd === -1) {
    console.error(`unable to read file ${module.path}, dump failed`)
    return null
  }

  console.log('decrypting module', module.name)

  const tmp = [NSTemporaryDirectory(), name, '.decrypted'].join('')
  const output = Memory.allocUtf8String(tmp)

  // copy encrypted
  const err = Memory.alloc(Process.pointerSize)
  const fileManager = ObjC.classes.NSFileManager.defaultManager()
  if (fileManager.fileExistsAtPath_(tmp))
    fileManager.removeItemAtPath_error_(tmp, err)
  fileManager.copyItemAtPath_toPath_error_(module.path, tmp, err)
  const desc = Memory.readPointer(err)
  if (!desc.isNull()) {
    console.error(`failed to copy file: ${new ObjC.Object(desc).toString()}`)
    return null
  }

  const outfd = open(output, O_RDWR, 0)

  // skip fat header
  const fatOffset = Process.findRangeByAddress(module.base).file.offset

  // dump decrypted
  lseek(outfd, fatOffset + encryptionInfo.offset, SEEK_SET)
  write(outfd, module.base.add(encryptionInfo.offset), encryptionInfo.size)

  /*
    https://developer.apple.com/documentation/kernel/encryption_info_command
    https://developer.apple.com/documentation/kernel/encryption_info_command_64
  */

  // erase cryptoff, cryptsize and cryptid
  const zeros = Memory.alloc(12)
  lseek(outfd, fatOffset + encryptionInfo.fileoff + 8, SEEK_SET) // skip cmd and cmdsize
  write(outfd, zeros, 12)
  close(outfd)

  return tmp
}


function transfer(task) {
  const { decrypted, relative, absolute } = task

  const path = decrypted || absolute
  const session = Math.random().toString(36).substr(2)
  const name = Memory.allocUtf8String(path)
  const watermark = 10 * 1024 * 1024
  const subject = 'download'
  const info = getFileInfo(path)
  const fd = open(name, 0, 0)
  if (fd === -1) {
    console.warn(`unable to open file ${path}, skip`)
    return Promise.resolve()
  }

  return new Promise((resolve, reject) => {
    const stream = new UnixInputStream(fd, { autoClose: true })
    const read = () => {
      stream.read(watermark).then((buffer) => {
        send({
          subject,
          event: 'data',
          session,
        }, buffer)
        if (buffer.byteLength === watermark) {
          setImmediate(read)
        } else {
          send({
            subject,
            event: 'end',
            session,
          })

          // delete intermediate file
          if (decrypted) {
            unlink(Memory.allocUtf8String(decrypted))
          }
          resolve()
        }
      }).catch((error) => {
        send({
          subject,
          event: 'error',
          session,
          error: error.message,
        })
        reject(error)
      })
    }
    send({
      subject,
      event: 'start',
      relative,
      session,
      info,
    })
    setImmediate(read)
  })
}

function normalize(path) {
  return path.replace(/^\/private\/var\//, '/var/')
}

rpc.exports = {
  dump: function() {
    const { NSBundle, NSFileManager, NSDirectoryEnumerator } = ObjC.classes
    const bundle = NSBundle.mainBundle().bundlePath().toString()
    const fileMgr = NSFileManager.defaultManager()
    const modules = Process.enumerateModulesSync()
      .map(mod => Object.assign({}, mod, { path: normalize(mod.path) }))
      .filter(mod => mod.path.startsWith(normalize(bundle)))
      .map(mod => ({
          relative: mod.path.substr(normalize(bundle).length).replace(/^\//, ''),
          absolute: mod.path,
          decrypted: dump(mod)
        }))

    const hashTable = {}
    for (let mod of modules)
      if (mod.decrypted)
        hashTable[mod.relative] = true

    const tasks = modules
    const enumerator = fileMgr.enumeratorAtPath_(bundle)
    let nextObj = null
    const isDir = Memory.alloc(Process.pointerSize)
    while (nextObj = enumerator.nextObject()) {
      const path = nextObj.toString()
      if (hashTable[path])
        continue

      const absolute = [bundle, path].join('/')
      Memory.writePointer(isDir, NULL)
      fileMgr.fileExistsAtPath_isDirectory_(absolute, isDir)
      if (Memory.readPointer(isDir).isNull()) {
        tasks.push({
          relative: path,
          absolute,
        })
      } else {
        send({ subject: 'mkdir', path })
      }
    }

    return new Promise((resolve, reject) => {
      const run = () => {
        const task = tasks.pop()
        if (task)
          transfer(task).then(run)
        else
          resolve()
      }
      run()
    })
  }
}
