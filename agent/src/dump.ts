import { memcpy, download } from './transfer';
import { normalize } from './path';
import { freeze, wakeup } from './threads';

const MH_MAGIC_64 = 0xfeedfacf;
const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;

type EncryptInfoTuple = [NativePointer, number, number, number, number];

interface Option {
  executableOnly?: boolean
}

function beep() {
  try {
    const SOUND = 1007
    const playSound = Module.findExportByName('AudioToolbox', 'AudioServicesPlaySystemSound')!
    new NativeFunction(playSound, 'void', ['int'])(SOUND)
  } catch (e) {

  }
}

export function base() {
  return normalize(ObjC.classes.NSBundle.mainBundle().bundlePath().toString());
}

function findCryptInfo(header: NativePointer) {
  const magic = header.readU32();
  if (magic !== MH_MAGIC_64) {
    throw new Error(`Unsupported magic ${magic.toString(16)}`);
  }

  const ncmds = header.add(16).readU32();
  const cmds = header.add(32);

  let offsetOfCmd = 0;
  let sizeOfCmd = 0;
  let offset = 0;
  let size = 0;

  for (let i = 0; i < ncmds; i++) {
    const cmd = cmds.add(offsetOfCmd).readU32();
    sizeOfCmd = cmds.add(offsetOfCmd + 4).readU32();

    if (cmd === LC_ENCRYPTION_INFO || cmd === LC_ENCRYPTION_INFO_64) {
      offset = cmds.add(offsetOfCmd + 8).readU32();
      size = cmds.add(offsetOfCmd + 12).readU32();
      return [cmds.add(offsetOfCmd), offset, size, offsetOfCmd, sizeOfCmd] as EncryptInfoTuple;
    }

    offsetOfCmd += sizeOfCmd;
  }

  throw new Error('Cannot find crypt info');  
}

export async function dump(opt: Option = {}) {
  // load all frameworks
  warmup();

  // freeze all threads
  freeze();

  const bundle = base();
  const downloaded = new Set<string>();
  for (let mod of Process.enumerateModules()) {
    const filename = normalize(mod.path);
    if (!filename.startsWith(bundle))
      continue;

    const info = findCryptInfo(mod.base) as EncryptInfoTuple;
    const [ptr, offset, size, offsetOfCmd, sizeOfCmd] = info;

    if (ptr.isNull())
      continue;

    await download(filename);
    downloaded.add(filename);

    // skip fat header
    const fatOffset = Process.findRangeByAddress(mod.base)!.file!.offset;

    // dump decrypted
    const session = memcpy(mod.base.add(offset), size);
    send({ subject: 'patch', offset: fatOffset + offset, blob: session, filename });

    // erase cryptoff
    send({ subject: 'patch', offset: fatOffset + offsetOfCmd, size: sizeOfCmd, filename });
  }

  wakeup();

  if (!opt.executableOnly)
    await pull(bundle, downloaded);

  beep();
  return 0;

}

async function pull(bundle: string, downloaded: Set<string>) {
  const manager = ObjC.classes.NSFileManager.defaultManager();
  const enumerator = manager.enumeratorAtPath_(bundle);
  const pIsDir = Memory.alloc(Process.pointerSize);
  const base = ObjC.classes.NSString.alloc().initWithString_(bundle);

  const skip = /\bSC\_Info\/((.+\.s(inf|up[fpx]))|Manifest\.plist)$/;

  let path: string;
  while ((path = enumerator.nextObject())) {
    if (skip.exec(path.toString()))
      continue;

    const fullname = normalize(base.stringByAppendingPathComponent_(path));
    if (downloaded.has(fullname))
      continue;

    pIsDir.writePointer(NULL);
    manager.fileExistsAtPath_isDirectory_(fullname, pIsDir);
    if (pIsDir.readPointer().isNull()) {
      await download(fullname);
    }
  }
}


export function warmup(): void {
  const { NSFileManager, NSBundle } = ObjC.classes
  const path = NSBundle.mainBundle().bundlePath().stringByAppendingPathComponent_('Frameworks')
  const mgr = NSFileManager.defaultManager()
  const pError = Memory.alloc(Process.pointerSize)
  pError.writePointer(NULL)
  const files = mgr.contentsOfDirectoryAtPath_error_(path, pError)
  const err = pError.readPointer()
  if (!err.isNull()) {
    const errObj = new ObjC.Object(err)
    const NSFileReadNoSuchFileError = 260
    if (errObj.code().valueOf() === NSFileReadNoSuchFileError)
      return
    return void console.error(new ObjC.Object(err))
  }

  const max = files.count()
  for (let i = 0; i < max; i++) {
    const name = files.objectAtIndex_(i)
    const bundle = NSBundle.bundleWithPath_(path.stringByAppendingPathComponent_(name))
    if (bundle)
      bundle.load()
  }
}

