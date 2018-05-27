Module.ensureInitialized('Foundation')


const { NSFileManager, NSURL, __NSCFNumber, __NSTaggedDate } = ObjC.classes
const { hasOwnProperty } = Object.prototype

export function NSTemporaryDirectory() {
  const func = new NativeFunction(Module.findExportByName(null, 'NSTemporaryDirectory'), 'pointer', [])
  const tmp = func()
  return tmp ? new ObjC.Object(tmp).toString() : null
}

export function getFileInfo(path) {
  const urlPath = NSURL.fileURLWithPath_(path)
  const pErr = Memory.alloc(Process.pointerSize)
  const dict = NSFileManager.defaultManager().attributesOfItemAtPath_error_(urlPath.path(), pErr)
  const err = Memory.readPointer(pErr)
  if (!err.isNull())
    throw new Error(new ObjC.Object(Memory.readPointer(err)))

  const lookup = {
    // owner: 'NSFileOwnerAccountName',
    size: 'NSFileSize',
    creation: 'NSFileCreationDate',
    permission: 'NSFilePosixPermissions',
    // type: 'NSFileType',
    // group: 'NSFileGroupOwnerAccountName',
    modification: 'NSFileModificationDate',
    // protection: 'NSFileProtectionKey',
  }

  const result = {}
  for (let key in lookup) {
    if (hasOwnProperty.call(lookup, key)) {
      const val = dict.objectForKey_(lookup[key])
      if (val.isKindOfClass_(__NSTaggedDate)) {
        result[key] = val.timeIntervalSince1970()
      } else if (val.isKindOfClass_(__NSCFNumber)) {
        result[key] = val.intValue()
      }
    }
  }

  return result
}
