interface Plugin {
  path: string,
  version: number,
  id: string,
  executable: string,
}

interface Context {
  cm?: CModule,
  findEncyptInfo?: NativeFunction,
}

interface NSString {
  UTF8String(): NativePointer,
}

interface NSDictionary {
  objectForKey_(key: string): any,
}

interface NSBundle {
  bundleIdentifier(): NSString,
  bundlePath(): NSString,
  infoDictionary(): NSDictionary,
  executablePath(): NSString,
}
