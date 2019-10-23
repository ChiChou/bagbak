export function plugins() {
  const directory = ObjC.classes.NSBundle.mainBundle().bundlePath().stringByAppendingPathComponent_('PlugIns');
  const manager = ObjC.classes.NSFileManager.defaultManager();
  const pError = Memory.alloc(Process.pointerSize);
  pError.writePointer(NULL);
  const list = manager.contentsOfDirectoryAtPath_error_(directory, pError);
  const err = pError.readPointer();
  const result: Plugin[] = [];
  if (!err.isNull()) {
    console.warn(`Failed to list plugins: ${new ObjC.Object(err).toString()}`);
    return result;
  }

  for (let i = 0; i < list.count(); i++) {
    const appex = directory.stringByAppendingPathComponent_(list.objectAtIndex_(i));
    const bundle = ObjC.classes.NSBundle.bundleWithPath_(appex);
    const version = bundle.infoDictionary().objectForKey_('CFBundleVersion').intValue();
    const id = bundle.bundleIdentifier().toString();
    const path = appex.toString();
    const executable = bundle.executablePath().toString();

    result.push({
      id,
      version,
      path,
      executable,
    });
    bundle.release();
  }

  return result;
}