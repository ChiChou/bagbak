interface Plugin {
  path: string,
  version: number,
  id: string,
  executable: string,
}

interface Context {
  cm?: CModule,
  findEncyptInfo?: NativeFunction<[NativePointer, number, number, number, number], [NativePointer]>,
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
