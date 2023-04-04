import { statSync } from "fs";

const open = new NativeFunction(Module.findExportByName(null, 'open')!, 'int', ['pointer', 'int']);
const close = new NativeFunction(Module.findExportByName(null, 'close')!, 'void', ['int']);
const read = new NativeFunction(Module.findExportByName(null, 'read')!, 'ssize_t', ['int', 'pointer', 'size_t']);

const O_RDONLY = 0;

const highWaterMark = 4 * 1024 * 1024;

function send2(payload: any, data?: ArrayBuffer | number[] | null) {
  send(payload, data);
  recv('ack', () => { }).wait();
}

const uuid = () => Math.random().toString(36).substring(2)

export function memcpy(address: NativePointer, size: number) {
  const session = uuid();
  
  const subject = 'memcpy';

  send2({
    subject,
    event: 'begin',
    session,
    size,
  })

  const count = Math.floor(size / highWaterMark);
  const tail = size % highWaterMark;
  let p = address;
  let i = 0;

  while (i++ < count) {
    send2({
      subject,
      event: 'data',
      session,
      index: i,
    }, p.readByteArray(highWaterMark));
    p = p.add(highWaterMark);
  }

  if (tail) {
    send2({
      subject,
      event: 'data',
      session,
      index: i,
    }, p.readByteArray(tail));
  }

  send({
    subject,
    event: 'end',
    session,
  });

  return session;
}

export async function download(filename: string) {
  const session = uuid();
  const subject = 'download';
  const { size, atimeMs, mtimeMs, mode } = statSync(filename);

  const buf = Memory.alloc(highWaterMark);
  const fd = open(Memory.allocUtf8String(filename), O_RDONLY) as number;

  if (fd < 0) throw new Error(`Unable to open file ${filename}`);

  send2({
    subject,
    event: 'begin',
    session,
    filename,
    stat: {
      size,
      atimeMs,
      mtimeMs,
      mode,
    },
  });

  while (true) {
    const size = (read(fd, buf, highWaterMark) as Int64).toNumber();
    if (size === 0) break;
    const chunk = buf.readByteArray(size);
    send2({
      subject,
      event: 'data',
      session,
    }, chunk);
  }

  send({
    subject,
    event: 'end',
    session,
  });

  close(fd);
}
