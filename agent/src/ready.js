const dlopen = new NativeFunction(Module.findExportByName(null, 'dlopen'), 'pointer', ['pointer', 'int'])
dlopen(Memory.allocUtf8String('/usr/lib/libarchive.dylib'), 0)
dlopen(Memory.allocUtf8String('/System/Library/Frameworks/Foundation.framework/Foundation'), 0)

Module.ensureInitialized('Foundation')
