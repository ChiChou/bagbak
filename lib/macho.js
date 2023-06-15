import { open, stat } from 'fs/promises';

/**
 * @typedef MachO
 * 
 * @property {string} path
 * @property {number} type
 * @property {EncryptInfo} encryptInfo
 * @property {number} encCmdOffset
 */

/**
 * @typedef EncryptInfo
 * 
 * @property {number} offset
 * @property {number} size
 * @property {number} id
 */


class InvalidMachOError extends Error {
  constructor(message) {
    super(message);
    this.name = 'InvalidMachOError';
  }
}

export const MH_EXECUTE = 0x2;
export const MH_DYLIB = 0x6;
export const MH_DYLINKER = 0x7;
export const MH_BUNDLE = 0x8;

/**
 * 
 * @param {PathLike} file 
 * @return {Promise<MachO>}
 */
export async function parse(file) {
  const MH_MAGIC_64 = 0xfeedfacf;
  const HEADER_SIZE_64 = 7 * 4;

  const stats = await stat(file);
  if (!stats.isFile()) {
    throw new Error(`${file} is not a file`);
  } else if (stats.size < HEADER_SIZE_64) {
    throw InvalidMachOError('file is too small');
  }

  const fd = await open(file, 'r');

  try {
    // nodejs doesn't have builtin mmap
    // use read instead

    const header = Buffer.alloc(HEADER_SIZE_64);
    await fd.read(header, 0, HEADER_SIZE_64, 0);
    const magic = header.readUInt32LE(0);
    if (MH_MAGIC_64 !== magic) {
      throw InvalidMachOError('file is not 64bit mach-o');
    }

    const fileType = header.readUInt32LE(12);
    const ncmds = header.readUInt32LE(16);
    const sizeOfCmds = header.readUInt32LE(20);

    if (sizeOfCmds + HEADER_SIZE_64 > stats.size) {
      throw InvalidMachOError('malformed mach-o');
    }

    const { buffer } = await fd.read(sizeOfCmds);
    const result = {
      path: file,
      type: fileType,
      encryptInfo: {
        offset: NaN,
        size: NaN,
        id: 0,
      },
      encCmdOffset: NaN
    }

    for (let offset = 32, i = 0; offset + 8 < buffer.length, i < ncmds; i++) {
      const cmd = buffer.readUInt32LE(offset);
      const cmdsize = buffer.readUInt32LE(offset + 4);
      if (cmd === 0x2c) {
        // LC_ENCRYPTION_INFO_64
        const cryptoff = buffer.readUInt32LE(offset + 4 * 2);
        const cryptsize = buffer.readUInt32LE(offset + 4 * 3);
        const cryptid = buffer.readUInt32LE(offset + 4 * 4);

        result.encryptInfo = {
          offset: cryptoff,
          size: cryptsize,
          id: cryptid,
        };

        result.encCmdOffset = offset;
      }
      offset += cmdsize;
    }

    return result;
  } finally {
    fd.close();
  }
}