import { createReadStream, statSync } from "fs";

function send2(payload: any, data?: ArrayBuffer | number[] | null | undefined) {
  send(payload, data);
  recv('ack', () => { }).wait();
}

export function memcpy(address: NativePointer, size: number) {
  const session = Math.random().toString(36).substr(2);
  const highWaterMark = 4 * 1024 * 1024;
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
  const session = Math.random().toString(36).substr(2);
  const highWaterMark = 4 * 1024 * 1024;
  const subject = 'download';
  const { size, atimeMs, mtimeMs, mode } = statSync(filename);
  const stream = createReadStream(filename, { highWaterMark });

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

  await new Promise((resolve, reject) =>
    stream
      .on('data', chunk => {
        send2({
          subject,
          event: 'data',
          session,
        }, chunk);
      })
      .on('end', resolve)
      .on('error', reject));

  send({
    subject,
    event: 'end',
    session,
  });

}
