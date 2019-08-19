import fs from 'frida-fs'
import macho from 'macho'

import './ready'
import { open, close, write, lseek, O_RDONLY, O_RDWR, SEEK_SET } from './libc'
import libarchive from './libarchive'
import * as path from './path'

import ReadOnlyMemoryBuffer from './romembuf'


function dump(module) {
  const { name } = module
  const buffer = new ReadOnlyMemoryBuffer(module.base, module.size)
  const info = macho.parse(buffer)
  const matches = info.cmds.filter(cmd => /^encryption_info(_64)?$/.test(cmd.type) && cmd.id === 1)
  if (!matches.length) {
    if (!name.match(/^libswift\w+\.dylib$/))
      console.warn(`Module ${name} is not encrypted`)
    return null
  }

  const encryptionInfo = matches.pop()
  const fd = open(Memory.allocUtf8String(module.path), O_RDONLY, 0)
  if (fd === -1) {
    console.error(`unable to read file ${module.path}, dump failed`)
    return null
  }
  close(fd)

  console.log('decrypting module', module.name)
  const tmp = path.join(tmpdir(), `${name}.decrypted`)

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

  const output = Memory.allocUtf8String(tmp)
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


async function transfer(filename) {
  const session = Math.random().toString(36).substr(2)
  const highWaterMark = 4 * 1024 * 1024
  const subject = 'download'
  const { size } = fs.statSync(filename)
  const stream = fs.createReadStream(filename, { highWaterMark })

  console.log('start transfering')
  send({
    subject,
    event: 'start',
    session,
    size,
  })

  const format = size => `${(size / 1024 / 1024).toFixed(2)}MiB`

  let sent = 0
  await new Promise((resolve, reject) =>
    stream
      .on('data', chunk => {
        send({
          subject,
          event: 'data',
          session,
        }, chunk)

        recv('flush', () => { }).wait()
        sent += chunk.byteLength
        console.log(`downloaded ${format(sent)} of ${format(size)}, ${(sent * 100 / size).toFixed(2)}%`)
      })
      .on('end', resolve)
      .on('error', reject))

  send({
    subject,
    event: 'end',
    session,
  })

  console.log('transfer complete')
  fs.unlinkSync(filename)

  try {
    const SOUND = 1007
    const playSound = Module.findExportByName('AudioToolbox', 'AudioServicesPlaySystemSound')
    new NativeFunction(playSound, 'void', ['int'])(SOUND)
  } catch (e) {

  }
}

const tmpdir = (function () {
  const f = new NativeFunction(Module.findExportByName(null, 'NSTemporaryDirectory'), 'pointer', [])
  const cache = new ObjC.Object(f()) + ''
  return () => cache
})()


rpc.exports = {
  plugins() {
    const {
      LSApplicationWorkspace,
      NSString,
      NSMutableArray,
      NSPredicate,
      NSBundle
    } = ObjC.classes

    const args = NSMutableArray.alloc().init()
    args.setObject_atIndex_(NSBundle.mainBundle().bundleIdentifier(), 0)
    const fmt = NSString.stringWithString_('containingBundle.applicationIdentifier=%@')
    const predicate = NSPredicate.predicateWithFormat_argumentArray_(fmt, args)
    const plugins = LSApplicationWorkspace.defaultWorkspace()
      .installedPlugins().filteredArrayUsingPredicate_(predicate)
    const result = []
    for (let i = 0; i < plugins.count(); i++) {
      result.push(plugins.objectAtIndex_(i).pluginIdentifier() + '')
    }
    args.release()
    return result
  },
  root() {
    return ObjC.classes.NSBundle.mainBundle().bundlePath().toString()
  },
  startPkd() {
    ObjC.classes.NSExtension.extensionWithIdentifier_error_('com.apple.nonexist', NULL)
  },
  launch(id) {
    const { NSExtension, NSString } = ObjC.classes
    const identifier = NSString.stringWithString_(id)
    const extension = NSExtension.extensionWithIdentifier_error_(identifier, NULL)
    if (!extension)
      throw new Error('unable to create extension ' + id)

    const pid = extension['- _plugInProcessIdentifier']()
    if (pid)
      return Promise.resolve(pid)

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        const pid = extension['- _plugInProcessIdentifier']()
        if (pid)
          resolve(pid)
        else
          reject('unable to get extension pid')
      }, 400)

      extension.beginExtensionRequestWithInputItems_completion_(NULL, new ObjC.Block({
        retType: 'void',
        argTypes: ['object'],
        implementation(requestIdentifier) {
          clearTimeout(timeout)
          const pid = extension.pidForRequestIdentifier_(requestIdentifier)
          resolve(pid)
        }
      }))
    })
  },
  decrypt(root) {
    const modules = Process.enumerateModulesSync()
      .map(mod => Object.assign({}, mod, { path: path.normalize(mod.path) }))
      .filter(mod => mod.path.startsWith(path.normalize(root)))
      .map(mod => ({
        relative: path.relativeTo(root, mod.path),
        absolute: mod.path,
        decrypted: dump(mod)
      }))
    return modules.filter(mod => mod.decrypted)
  },
  async archive(root, decrypted, opt) {
    const pkg = path.join(tmpdir(), `${Math.random().toString(36).slice(2)}.ipa`)
    console.log('compressing archive:', pkg)

    const ar = libarchive.writeNew()
    libarchive.writeSetFormatZip(ar)
    libarchive.writeOpenFilename(ar, Memory.allocUtf8String(pkg))

    const { NSFileManager } = ObjC.classes
    const fileMgr = NSFileManager.defaultManager()
    const enumerator = fileMgr.enumeratorAtPath_(root)

    const highWaterMark = 16 * 1024 * 1024
    const buf = Memory.alloc(highWaterMark)
    const prefix = path.join('Payload', path.basename(root))

    const timestamp = date => Math.floor(date.getTime() / 1000)
    const lookup = {}
    for (let mod of decrypted)
      lookup[mod.relative] = mod

    let nextObj = null
    while (nextObj = enumerator.nextObject()) {
      const relative = nextObj.toString()
      if (/(\_CodeSignature\/CodeResources|SC_Info\/\w+\.s(inf|upf|upp|upx))$/.test(relative))
        continue

      if (!opt.keepWatch && /^Watch\//.test(relative))
        continue

      const absolute = path.join(root, relative)
      const st = fs.statSync(absolute)
      if (st.mode & fs.constants.S_IFDIR) {
        // doesn't need to handle?
        continue
      } else if (!(st.mode & fs.constants.S_IFREG)) {
        console.error('unknown file mode', absolute)
      }

      if (opt.verbose)
        console.log('compress:', relative)

      const entry = libarchive.entryNew()
      libarchive.entrySetPathname(entry, Memory.allocUtf8String(path.join(prefix, relative)))
      libarchive.entrySetSize(entry, st.size)
      libarchive.entrySetFiletype(entry, fs.constants.S_IFREG)
      libarchive.entrySetPerm(entry, st.mode & 0o777)
      libarchive.entrySetCtime(entry, timestamp(st.ctime), 0)
      libarchive.entrySetMtime(entry, timestamp(st.mtime), 0)
      libarchive.writeHeader(ar, entry)

      const filename = relative in lookup ? lookup[relative].decrypted : absolute
      let stream
      try {
        stream = fs.createReadStream(filename, { highWaterMark })
      } catch (e) {
        if (!/(\/Plugins\/(.*)\.appex\/)?SC_Info\//.test(relative))
          console.warn(`unable to open ${filename} (${e.message})`)
        continue
      }

      await new Promise((resolve, reject) =>
        stream
          .on('data', chunk => {
            Memory.writeByteArray(buf, chunk)
            libarchive.writeData(ar, buf, chunk.byteLength)
          })
          .on('end', resolve)
          .on('error', reject))

      // delete decrypted file
      if (relative in lookup)
        fs.unlinkSync(filename)

      libarchive.writeFinishEntry(ar)
      libarchive.entryFree(entry)
    }

    libarchive.writeFinish(ar)
    console.log('done', pkg)
    return transfer(pkg)
  },
  skipPkdValidationFor(pid) {
    if ('PKDPlugIn' in ObjC.classes) {
      const method = ObjC.classes.PKDPlugIn['- allowForClient:']
      const original = method.implementation
      method.implementation = ObjC.implement(method, function (self, sel, conn) {
        // race condition huh? we don't care
        return pid === new ObjC.Object(conn).pid() ? NULL : original.call(this, arguments)
      })
    }
  }
}
