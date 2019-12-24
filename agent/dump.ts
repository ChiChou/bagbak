import { memcpy, download } from './transfer';
import { normalize } from './path';
import { freeze, wakeup } from './threads';

type EncryptInfoTuple = [NativePointer, number, number, number, number];

interface ISet {
  [key: string]: boolean;
}

interface Option {
  executableOnly?: boolean
}

const ctx: Context = {};
const EncryptInfoTuple = ['pointer', 'uint32', 'uint32', 'uint32', 'uint32'];

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

export async function dump(opt: Option = {}) {
  // A song of ice & fire

  // load all frameworks
  warmup();

  // freeze all threads
  freeze();

  const bundle = base();
  const downloaded: ISet = {};
  for (let mod of Process.enumerateModules()) {
    const filename = normalize(mod.path);
    if (!normalize(filename).startsWith(bundle))
      continue;

    const info = ctx.findEncyptInfo!(mod.base) as EncryptInfoTuple;
    const [ptr, offset, size, offsetOfCmd, sizeOfCmd] = info;

    if (ptr.isNull())
      continue;

    await download(filename);
    downloaded[filename] = true;

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

async function pull(bundle: string, downloaded: ISet) {
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
    if (downloaded[fullname])
      continue;

    pIsDir.writePointer(NULL);
    manager.fileExistsAtPath_isDirectory_(fullname, pIsDir);
    if (pIsDir.readPointer().isNull()) {
      await download(fullname);
    }
  }
}

export function prepare(c: string) {
  const cm = new CModule(c);
  ctx.cm = cm
  ctx.findEncyptInfo = new NativeFunction(cm['find_encryption_info'], EncryptInfoTuple, ['pointer']);
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

