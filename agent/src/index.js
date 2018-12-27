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
    if (!path.match(/\.s(inf|up[fpx])$/))
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
  plugins: function() {
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
  start: function(id) {
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
  dump: function(opt) {
    const { NSBundle, NSFileManager, NSDirectoryEnumerator } = ObjC.classes
    const bundle = NSBundle.mainBundle().bundlePath()
    const appName = bundle.lastPathComponent()
    const payload = (path) => [appName, path].join('/')

    const fileMgr = NSFileManager.defaultManager()
    const modules = Process.enumerateModulesSync()
      .map(mod => Object.assign({}, mod, { path: normalize(mod.path) }))
      .filter(mod => mod.path.startsWith(normalize(bundle)))
      .map(mod => ({
          relative: relativeTo(bundle, mod.path),
          absolute: mod.path,
          decrypted: dump(mod)
        }))

    send({ subject: 'mkdir', path: appName.toString() })
    const hashTable = {}
    for (let mod of modules)
      if (mod.decrypted)
        hashTable[mod.relative] = true

    const tasks = modules.map(mod => Object.assign(mod, {
      relative: payload(mod.relative)
    }))
    const isDir = Memory.alloc(Process.pointerSize)
    const enumerator = fileMgr.enumeratorAtPath_(bundle)
    let nextObj = null
    while (nextObj = enumerator.nextObject()) {
      const path = nextObj.toString()
      if (hashTable[path])
        continue

      if (!opt.keepWatch && (path + '/').startsWith('Watch/'))
        continue // skip WatchOS related app

      const absolute = [bundle, path].join('/')
      Memory.writePointer(isDir, NULL)
      fileMgr.fileExistsAtPath_isDirectory_(absolute, isDir)
      if (Memory.readPointer(isDir).isNull()) {
        tasks.push({
          relative: payload(path),
          absolute,
        })
      } else {
        send({ subject: 'mkdir', path: payload(path) })
      }
    }

    console.log('start downloading files')
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
