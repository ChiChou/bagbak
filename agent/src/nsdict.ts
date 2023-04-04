const {
  NSMutableDictionary, NSMutableArray, NSString,
  NSNull, __NSCFBoolean
} = ObjC.classes


export function toNSObject(obj: any) {
  if (typeof obj === 'boolean')
    return __NSCFBoolean.numberWithBool_(obj);
  if (typeof obj === 'undefined' || obj === null)
    return NSNull.null();
  if (typeof obj === 'string')
    return NSString.stringWithString_(obj);
  if (typeof obj === 'object' && 'isKindOfClass_' in obj)
    return obj;

  if (Array.isArray(obj)) {
    const mutableArray = NSMutableArray.alloc().init();
    obj.forEach(item => mutableArray.addObject_(toNSObject(item)));
    return mutableArray;
  }

  const mutableDict = NSMutableDictionary.alloc().init();
  for (const key in obj) {
    const val = toNSObject(obj[key]);
    mutableDict.setObject_forKey_(val, key);
  }

  return mutableDict;
}