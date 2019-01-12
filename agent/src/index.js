import fs from 'frida-fs'
import macho from 'macho'

import libarchive from './libarchive'

import { open, close, write, lseek, O_RDONLY, O_RDWR, SEEK_SET } from './libc'
import ReadOnlyMemoryBuffer from './romembuf'


function dump(module, dest) {
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
  close(fd)

  console.log('decrypting module', module.name)

  const tmp = [dest, '/', name, '.decrypted'].join('')

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
  const watermark = 10 * 1024 * 1024
  const subject = 'download'
  const { size } = fs.statSync(filename)
  const fd = open(Memory.allocUtf8String(filename), O_RDONLY, 0)

  if (fd === -1)
    throw new Error('fatal error: unable to download archive')

  const stream = new UnixInputStream(fd, { autoClose: true })
  let eof = false
  send({
    subject,
    event: 'start',
    session,
    size,
  })

  while (!eof) {
    const bytes = await stream.read(watermark)
    eof = bytes.byteLength < watermark

    send({
      subject,
      event: 'data',
      session,
    }, bytes)
  }

  send({
    subject,
    event: 'end',
    session,
  })

  fs.unlinkSync(filename)

  try {
    const SOUND = 1007
    const playSound = Module.findExportByName('AudioToolbox', 'AudioServicesPlaySystemSound')
    new NativeFunction(playSound, 'void', ['int'])(SOUND)
  } catch (e) {

  }
}

function relativeTo(base, full) {
  const a = normalize(base).split('/')
  const b = normalize(full).split('/')

  let i = 0;
  while (a[i] === b[i])
    i++
  return b.slice(i).join('/')
}

function normalize(path) {
  return ObjC.classes.NSString.stringWithString_(path)
    .stringByStandardizingPath().toString()
}

rpc.exports = {
  pathForGroup(group) {
    return ObjC.classes.NSFileManager.defaultManager()
      .containerURLForSecurityApplicationGroupIdentifier_(group)
      .path()
      .toString();
  },
  plugins() {
    const {
      LSApplicationWorkspace,
      NSString,
      NSMutableArray,
      NSPredicate,
      NSBundle
    } = ObjC.classes;

    const args = NSMutableArray.alloc().init();
    args.setObject_atIndex_(NSBundle.mainBundle().bundleIdentifier(), 0);
    const fmt = NSString.stringWithString_('containingBundle.applicationIdentifier=%@');
    const predicate = NSPredicate.predicateWithFormat_argumentArray_(fmt, args);
    const plugins = LSApplicationWorkspace.defaultWorkspace()
      .installedPlugins().filteredArrayUsingPredicate_(predicate);
    const result = [];
    for (let i = 0; i < plugins.count(); i++) {
      result.push(plugins.objectAtIndex_(i).pluginIdentifier() + '');
    }
    return result;
  },
  root() {
    return ObjC.classes.NSBundle.mainBundle().bundlePath().toString()
  },
  groups() {
    const createFromSelf = new NativeFunction(
      Module.findExportByName('Security', 'SecTaskCreateFromSelf'),
      'pointer', ['pointer']);
    const task = createFromSelf(NULL);
    const copyTaskEnt = new NativeFunction(
      Module.findExportByName('Security', 'SecTaskCopyValueForEntitlement'),
      'pointer', ['pointer', 'pointer', 'pointer']);
    const key = ObjC.classes.NSString.stringWithString_('com.apple.security.application-groups')
    // todo: copy to array
    const value = new ObjC.Object(copyTaskEnt(task, key, NULL));
    const result = [];
    for (let i = 0; i < value.count(); i++) {
      result.push(value.objectAtIndex_(i) + '');
    }
    return result;
  },
  launch(id) {
    const { NSExtension, NSString } = ObjC.classes;
    const pErr = Memory.alloc(Process.pointerSize);
    const identifier = NSString.stringWithString_(id);
    const extension = NSExtension.extensionWithIdentifier_error_(identifier, pErr);
    const err = Memory.readPointer(pErr);
    if (!err.isNull()) {
      console.log('err:', new ObjC.Object(err))
      return Promise.reject(new ObjC.Object(err).toString())
    }

    if (!extension) {
      return Promise.reject('unable to create extension ' + id);
    }

    // https://ianmcdowell.net/blog/nsextension/
    return new Promise((resolve, reject) => {
      extension.beginExtensionRequestWithInputItems_completion_(NULL, new ObjC.Block({
        retType: 'void',
        argTypes: ['object'],
        implementation(requestIdentifier) {
          const pid = extension.pidForRequestIdentifier_(requestIdentifier);
          resolve(pid);
        }
      }));
    });
  },
  decrypt(root, dest) {
    const modules = Process.enumerateModulesSync()
      .map(mod => Object.assign({}, mod, { path: normalize(mod.path) }))
      .filter(mod => mod.path.startsWith(normalize(root)))
      .map(mod => ({
        relative: relativeTo(root, mod.path),
        absolute: mod.path,
        decrypted: dump(mod, dest)
      }))
    return modules.filter(mod => mod.decrypted)
  },
  async archive(root, dest, decrypted, opt) {
    const pkg = `${dest}/archive.ipa`
    const ar = libarchive.writeNew()
    libarchive.writeSetFormatZip(ar)
    libarchive.writeOpenFilename(ar, Memory.allocUtf8String(pkg))

    const { NSFileManager } = ObjC.classes
    const fileMgr = NSFileManager.defaultManager()
    const enumerator = fileMgr.enumeratorAtPath_(root)

    const bufferSize = 16 * 1024 * 1024
    const buf = Memory.alloc(bufferSize)

    const timestamp = date => Math.floor(date.getTime() / 1000)
    const lookup = {}
    for (let mod of decrypted)
      lookup[mod.relative] = mod

    let nextObj = null
    while (nextObj = enumerator.nextObject()) {
      const path = nextObj.toString()
      const absolute = [root, path].join('/')
      const st = fs.statSync(absolute)
      if (st.mode & fs.constants.S_IFDIR) {
        // doesn't need to handle?
        continue
      } else if (!(st.mode & fs.constants.S_IFREG)) {
        console.warn('unknown file mode', absolute)
      }

      const entry = libarchive.entryNew()
      libarchive.entrySetPathname(entry, Memory.allocUtf8String(path))
      libarchive.entrySetSize(entry, st.size)
      libarchive.entrySetFiletype(entry, fs.constants.S_IFREG)
      libarchive.entrySetPerm(entry, st.mode & 0o777)
      libarchive.entrySetCtime(entry, timestamp(st.ctime), 0)
      libarchive.entrySetMtime(entry, timestamp(st.mtime), 0)
      libarchive.writeHeader(ar, entry)

      // const stream = fs.createReadStream(absolute)
      const filename = path in lookup ? lookup[path].decrypted : absolute
      const fd = open(Memory.allocUtf8String(filename), O_RDONLY, 0)
      if (fd === -1) {
        if (/\/CodeResources\//.test(path) || /(\/Plugins\/(.*)\.appex\/)?SC_Info\//.test(path))
          continue

        console.warn('unable to open', absolute)
        continue
      }

      const stream = new UnixInputStream(fd, { autoClose: true });
      let eof = false
      while (!eof) {
        const bytes = await stream.read(bufferSize)
        eof = bytes.byteLength < bufferSize
        // damn memcpy
        Memory.writeByteArray(buf, bytes)
        libarchive.writeData(ar, buf, bytes.byteLength)
      }

      // delete decrypted file
      if (path in lookup)
        fs.unlinkSync(filename)

      console.log('compress:', path)
      libarchive.writeFinishEntry(ar)
      libarchive.entryFree(entry)
    }

    libarchive.writeFinish(ar)
    console.log('archive:', pkg)
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
