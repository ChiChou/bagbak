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
    // bundle.release();
  }

  return result;
}

export function launch(id: string) {
  const { NSExtension, NSString } = ObjC.classes;

  const identifier = NSString.stringWithString_(id);
  const extension = NSExtension.extensionWithIdentifier_error_(identifier, NULL);
  identifier.release();
  if (!extension)
    return Promise.reject(`unable to create extension ${id}`);

  const pid = extension['- _plugInProcessIdentifier']();
  if (pid)
    return Promise.resolve(pid);

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      const pid = extension['- _plugInProcessIdentifier']();
      extension.release();
      if (pid)
        resolve(pid);
      else
        reject('unable to get extension pid');
    }, 400)

    extension.beginExtensionRequestWithInputItems_completion_(NULL, new ObjC.Block({
      retType: 'void',
      argTypes: ['object'],
      implementation(requestIdentifier) {
        clearTimeout(timeout);
        const pid = extension.pidForRequestIdentifier_(requestIdentifier);
        extension.release();
        resolve(pid);
      }
    }))
  })
}

export function launchAll() {
  return Promise.all(plugins().map(({ id }) => launch(id)));
}

export function jetsam(pid: number) {
  const MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT = 6;
  const p = Module.findExportByName(null, 'memorystatus_control')!;
  const memctl = new NativeFunction(p, 'int', ['uint32', 'int32', 'uint32', 'pointer', 'uint32']);
  return memctl(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, pid, 256, NULL, 0);
}
