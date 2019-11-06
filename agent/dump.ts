import { memcpy, download } from './transfer';
import { normalize } from './path';

type EncryptInfoTuple = [NativePointer, number, number, number, number];


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

export async function dump() {
  // A song of ice & fire

  // load all frameworks
  warmup();

  // freeze all threads
  freeze();

  const bundle = base();
  for (let mod of Process.enumerateModules()) {
    const filename = normalize(mod.path)
    if (!normalize(filename).startsWith(bundle))
      continue;

    const info = ctx.findEncyptInfo!(mod.base) as EncryptInfoTuple;
    const [ptr, offset, size, offsetOfCmd, sizeOfCmd] = info;

    if (ptr.isNull())
      continue;

    await download(filename);

    // skip fat header
    const fatOffset = Process.findRangeByAddress(mod.base)!.file!.offset;

    // todo: filename argument
    // dump decrypted
    const session = memcpy(mod.base.add(offset), size);
    send({ subject: 'patch', offset: fatOffset + offset, blob: session, filename });

    // erase cryptoff
    send({ subject: 'patch', offset: fatOffset + offsetOfCmd, size: sizeOfCmd, filename });
  }

  wakeup();
  beep();
  return 0;
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
  if (!err.isNull())
    return void console.error(new ObjC.Object(err))
  
  const max = files.count()
  for (let i = 0; i < max; i++) {
    const name = files.objectAtIndex_(i)
    const bundle = NSBundle.bundleWithPath_(path.stringByAppendingPathComponent_(name))
    bundle.load()
  }
}

const suspend = new NativeFunction(Module.findExportByName('libsystem_kernel.dylib', 'thread_suspend')!, 'pointer', ['uint']);
const resume = new NativeFunction(Module.findExportByName('libsystem_kernel.dylib', 'thread_resume')!, 'pointer', ['uint']);

export function freeze() {
  for (let { id } of Process.enumerateThreads())
    suspend(id)
}

export function wakeup() {
  for (let { id } of Process.enumerateThreads())
    resume(id)
}