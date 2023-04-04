export interface Plugin {
  path: string,
  version: number,
  id: string,
  executable: string,
}

export interface NSString {
  UTF8String(): NativePointer,
}

export interface NSDictionary {
  objectForKey_(key: string): any,
}

export interface NSBundle {
  bundleIdentifier(): NSString,
  bundlePath(): NSString,
  infoDictionary(): NSDictionary,
  executablePath(): NSString,
}
