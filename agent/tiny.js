Module.ensureInitialized('Foundation');

if (!ObjC.available)
  throw new Error('Objective-C Runtime is not available!');

const HIGH_WATER_MARK = 1024 * 1024;

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

rpc.exports = {
  /**
   * @param {string} root
   * @param {[string, MachO][]} dylibs 
   * @returns 
   */
  newDump(root, dylibs) {
    const main = ObjC.classes.NSBundle.mainBundle();
    const mainExecutable = main.executablePath();

    for (const [relative, info] of dylibs) {
      const basename = relative.split('/').pop();
      const { offset, size, id } = info.encryptInfo;

      if (!id) continue;

      const dylibPath = [root, relative].join('/');
      if (dylibPath !== mainExecutable.toString()) {
        Module.load(dylibPath);
      }

      const mod = Process.findModuleByName(basename.toString());
      const fatOffset = Process.findRangeByAddress(mod.base).file.offset;

      send({ event: 'begin', name: relative, fatOffset });
      recv('ack').wait();

      console.log('module =>', mod.name, mod.base, mod.size);
      console.log('encrypted =>', offset, size);

      {
        let fileOffset = offset + fatOffset;

        const steps = Math.floor(size / HIGH_WATER_MARK);

        let remain = size;
        let p = mod.base.add(offset);

        for (let i = 0; i < steps; i++) {          
          console.log('ptr', p);
          send({ event: 'trunk', fileOffset, name: relative }, p.readByteArray(HIGH_WATER_MARK));
          recv('ack').wait();

          remain -= HIGH_WATER_MARK;
          fileOffset += HIGH_WATER_MARK;
          p = p.add(HIGH_WATER_MARK);
        }

        if (remain > 0) {
          fileOffset += HIGH_WATER_MARK;
          send({ event: 'trunk', fileOffset, name: relative }, p.readByteArray(remain));
          recv('ack').wait();
        }
      }

      send({ event: 'end', name: relative, flagOffset: info.encCmdOffset + 16 });
      recv('ack').wait();
    }

    return 'ok';
  }
}