Module.ensureInitialized('Foundation');

if (!ObjC.available)
  throw new Error('Objective-C Runtime is not available!');

const HIGH_WATER_MARK = 1024 * 1024;

function memcpy() {
  // todo
}

rpc.exports = {
  newDump(dylibs) {
    const root = ObjC.classes.NSBundle.mainBundle().bundlePath();
    for (const [path, encryptedInfo] of dylibs) {
      /**
       * @type {ObjC.Object}
       */
      const dylibPath = root.stringByAppendingPathComponent_(path);

      // todo: declare NSString interface

      /**
       * @type {ObjC.Object}
       */
      const basename = dylibPath.lastPathComponent();
      console.log(dylibPath, dylibPath.UTF8String());
      Module.load(dylibPath.toString());

      const mod = Process.findModuleByName(basename.toString());
      // todo: memcpy
    }

    return 'ok';
  }
}