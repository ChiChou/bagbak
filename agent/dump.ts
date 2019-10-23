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

export async function dump() {
  const bundle = normalize(ObjC.classes.NSBundle.mainBundle().bundlePath().toString());
  for (let mod of Process.enumerateModules()) {
    if (!normalize(mod.path).startsWith(bundle))
      continue;

    const info = ctx.findEncyptInfo!(mod.base) as EncryptInfoTuple;
    const [ptr, offset, size, offsetOfCmd, sizeOfCmd] = info;

    if (ptr.isNull())
      continue;

    await download(mod.path);

    // skip fat header
    const fatOffset = Process.findRangeByAddress(mod.base)!.file!.offset;

    // todo: filename argument
    // dump decrypted
    const session = memcpy(mod.base.add(offset), size);
    send({ subject: 'patch', offset: fatOffset + offset, blob: session, filename: mod.path });

    // erase cryptoff
    send({ subject: 'patch', offset: fatOffset + offsetOfCmd, size: sizeOfCmd, filename: mod.path });
  }

  beep();
  return 0;
}

export function prepare(c: string) {
  const cm = new CModule(c);
  ctx.cm = cm
  ctx.findEncyptInfo = new NativeFunction(cm['find_encryption_info'], EncryptInfoTuple, ['pointer']);
}
