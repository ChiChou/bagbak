import { toNSObject } from "./nsdict";

export const add = new NativeFunction(
  Module.findExportByName('libxpc.dylib', 'launch_add_external_service')!,
  'uint',
  ['int', 'pointer', 'pointer'],
);

export const remove = new NativeFunction(
  Module.findExportByName('libxpc.dylib', 'launch_remove_external_service')!,
  'void',
  ['pointer', 'pointer', 'pointer', 'pointer'],
);

export const XPCFromCF = new NativeFunction(
  Module.findExportByName('CoreFoundation', '_CFXPCCreateXPCObjectFromCFObject')!,
  'pointer',
  ['pointer']
);

export function launch(pid: number, path: string, env: any) {
  const param = XPCFromCF(toNSObject({
    XPCService: {
      RunLoopType: '_UIApplicationMain',
      _SandboxProfile: 'plugin',
      _AdditionalSubServices: {
        viewservice: true,
        'apple-extension-service': true,
      },
      EnvironmentVariables: env,
      _OmitSandboxParameters: true,
      ServiceType: 'Application',
    },
    CFBundlePackageType: 'XPC!',
  }))

  console.log(new ObjC.Object(param as NativePointer));

  const ret = add(pid, Memory.allocUtf8String(path), param);
  new ObjC.Object(param as NativePointer).release();
  return ret;
}

export function stop(plugin: Plugin) {
  // Module.findExportByName('libdispatch.dylib', 'dispatch_queue_create')
  // Module.findExportByName('libdispatch.dylib', 'dispatch_release')

  const mainQueue = new NativeFunction(
    Module.findExportByName('libdispatch.dylib', 'dispatch_get_main_queue')!,
    'pointer', [])
  
  const block = new ObjC.Block({
    retType: 'void',
    argTypes: ['object'],
    implementation: function() {
      console.log('done')
    }
  });

  remove(
    Memory.allocUtf8String(plugin.id),
    plugin.version,
    mainQueue(),
    block.handle);
}

// bundleIdentifier, CFBundleVersion, dispatch_queue_create("killer", 0LL), block
