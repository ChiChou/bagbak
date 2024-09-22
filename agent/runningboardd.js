Module.load('/usr/lib/system/libxpc.dylib');

// todo: get ride of AppServerSupport SPI, use launchd directly
Module.load('/System/Library/PrivateFrameworks/AppServerSupport.framework/AppServerSupport');
Module.load('/System/Library/Frameworks/Foundation.framework/Foundation') // _CFXPCCreateXPCObjectFromCFObject
Module.load('/System/Library/Frameworks/CoreServices.framework/CoreServices') // LSBundleProxy

const libxpc = Process.findModuleByName('libxpc.dylib');

const xpc_array_create_empty = new NativeFunction(libxpc.findExportByName('xpc_array_create_empty'), 'pointer', []);
const xpc_array_append_value = new NativeFunction(libxpc.findExportByName('xpc_array_append_value'), 'void', ['pointer', 'pointer']);

const xpc_string_create = new NativeFunction(libxpc.findExportByName('xpc_string_create'), 'pointer', ['pointer']);

const xpc_dictionary_create_empty = new NativeFunction(libxpc.findExportByName('xpc_dictionary_create_empty'), 'pointer', []);

const xpc_dictionary_set_int64 = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_int64'), 'void', ['pointer', 'pointer', 'int64']);
const xpc_dictionary_set_uint64 = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_uint64'), 'void', ['pointer', 'pointer', 'uint64']);
const xpc_dictionary_set_string = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_string'), 'void', ['pointer', 'pointer', 'pointer']);
const xpc_dictionary_set_value = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_value'), 'void', ['pointer', 'pointer', 'pointer']);
const xpc_dictionary_set_bool = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_bool'), 'void', ['pointer', 'pointer', 'bool']);

const xpc_copy_description = new NativeFunction(libxpc.findExportByName('xpc_copy_description'), 'pointer', ['pointer']);
const xpc_release = new NativeFunction(libxpc.findExportByName('xpc_release'), 'void', ['pointer']);

const free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer']);

const _launch_job_routine = new NativeFunction(Module.findExportByName(null, '_launch_job_routine'), 'pointer', ['int', 'pointer', 'pointer']);

const _CFXPCCreateXPCObjectFromCFObject = new NativeFunction(
  Module.findExportByName('Foundation', '_CFXPCCreateXPCObjectFromCFObject'), 'pointer', ['pointer']);

const xpcServiceKeys = [
  'RunLoopType',
  'ServiceType',
  'JoinExistingSession',
  'EnvironmentVariables',
  '_AdditionalSubServices'
]

/**
 * @param {NativePointer} xpcObj 
 * @returns {string}
 */
function xpcDescription(xpcObj) {
  if (xpcObj.isNull()) return '(NULL)';
  const desc = xpc_copy_description(xpcObj);
  const result = desc.readUtf8String();
  free(desc);
  return result;
}

/**
 * 
 * @param {(pError: NativePointer) => ObjC.Object} func 
 */
function throwsNSError(func) {
  const pError = Memory.alloc(Process.pointerSize).writePointer(NULL);
  const result = func(pError);
  const error = pError.readPointer();
  if (!error.isNull()) {
    throw new Error(new ObjC.Object(error).toString());
  }
  return result;
}

const CSTR = s => Memory.allocUtf8String(s);

/**
 * 
 * @param {string} bundleId identifier of extension
 * @param {number} host pid of host process
 */
rpc.exports.kickstart = function (bundleId, host) {
  const plugin = ObjC.classes.LSBundleProxy.bundleProxyForIdentifier_(bundleId);

  if (!plugin) throw new Error(`bundle ${bundleId} not found`);

  const infoPlist = plugin.infoPlist();
  const container = plugin.containerURL().path().toString();

  const xpcInfo = infoPlist.objectForKey_('XPCService');
  const path = infoPlist.objectForKey_('Path') + '/' + infoPlist.objectForKey_('CFBundleExecutable');
  const overlay = xpc_dictionary_create_empty();
  {
    const xpcService = _CFXPCCreateXPCObjectFromCFObject(xpcInfo || ObjC.classes.NSDictionary.dictionary());
    // xpc_dictionary_set_int64(xpcService, CSTR('_LaunchWatchdogTimeOut'), 100);
    // xpc_dictionary_set_string(xpcService, CSTR('_SandboxProfile'), CSTR('plugin'));
    // xpc_dictionary_set_int64(xpcService, CSTR('Platform'), 2);
    // xpc_dictionary_set_int64(xpcService, CSTR('PersonaEnterprise'), 1000);
    // xpc_dictionary_set_bool(xpcService, CSTR('_OmitSandboxParameters'), 1);

    const env = xpc_dictionary_create_empty();
    {
      xpc_dictionary_set_string(env, CSTR('TMPDIR'), CSTR(container + '/tmp'));
      xpc_dictionary_set_string(env, CSTR('HOME'), CSTR(container));
      xpc_dictionary_set_string(env, CSTR('CFFIXED_USER_HOME'), CSTR(container));
    }

    xpc_dictionary_set_value(xpcService, CSTR('EnvironmentVariables'), env);

    // jetsam hack doesn't work here
    // todo: find out the reason
    const jetsam = xpc_dictionary_create_empty();
    {
      xpc_dictionary_set_int64(jetsam, CSTR('JetsamPriority'), 14);
      xpc_dictionary_set_int64(jetsam, CSTR('ActiveHardMemoryLimit'), 50);
      xpc_dictionary_set_int64(jetsam, CSTR('InactiveHardMemoryLimit'), 50);
    }
    xpc_dictionary_set_value(xpcService, CSTR('JetsamProperties'), jetsam);
    xpc_dictionary_set_bool(xpcService, CSTR('WaitForDebugger'), 1);
    //

    xpc_dictionary_set_string(overlay, CSTR('CFBundlePackageType'), CSTR('XPC!'));
    xpc_dictionary_set_value(overlay, CSTR('XPCService'), xpcService);
  }

  // hack jatsam end

  // const runningboard = xpc_dictionary_create_empty();
  // {
  //   xpc_dictionary_set_bool(runningboard, CSTR('Managed'), 1);
  //   xpc_dictionary_set_bool(runningboard, CSTR('RunningBoardLaunched'), 1);

  //   const identity = xpc_dictionary_create_empty(); {
  //     xpc_dictionary_set_int64(identity, CSTR('h'), pid);
  //     xpc_dictionary_set_string(identity, CSTR('i'), CSTR(plugin.bundleIdentifier().toString()));
  //   }
  //   xpc_dictionary_set_value(runningboard, CSTR('RunningBoardLaunchedIdentity'), identity);
  // }
  // xpc_dictionary_set_value(overlay, CSTR('RunningBoard'), runningboard);

  // const addictional = xpc_dictionary_create_empty();
  // {
  //   xpc_dictionary_set_value(overlay, CSTR('_AdditionalProperties'), addictional);
  // }
  // xpc_dictionary_set_value(addictional, CSTR('RunningBoard'), runningboard);

  // console.log(xpcDescription(overlay));

  const domain = ObjC.classes.OSLaunchdDomain.domainForPid_(host);

  let job = throwsNSError((pError) =>
    ObjC.classes.OSLaunchdJob.submitExtension_overlay_domain_error_(path, overlay, domain, pError));

  if (xpcInfo?.objectForKey_('_MultipleInstances')?.boolValue()) {
    const uuid = Memory.allocUtf8String('A'.repeat(256));
    job = throwsNSError((pError) => job.createInstance_error_(uuid, pError));
  }

  const result = throwsNSError((pError) => job.start_(pError));
  return result.pid();
}

function getApp(bundleId) {
  const app = ObjC.classes.LSApplicationProxy.applicationProxyForIdentifier_(bundleId);
  if (!app) throw new Error(`app ${bundleId} not found`);
  return app;
}

/**
 * submit process to launchd
 * @param {NativePointer} plist xpc_dictionary
 * @returns {number} pid of the job
 */
function submit(plist) {
  const job = ObjC.classes.OSLaunchdJob.alloc().initWithPlist_(plist);
  const result = throwsNSError((pError) => job.submitAndStart_(pError));
  return result.pid();
}

/**
 * spawn app in the **background**
 * @param {*} bundleId 
 */
rpc.exports.spawn = function (bundleId) {
  const app = getApp(bundleId);
  const plist = xpc_dictionary_create_empty();
  // xpc_dictionary_set_string(plist, CSTR('ProcessType'), CSTR('App'));
  xpc_dictionary_set_string(plist, CSTR('UserName'), CSTR('mobile'));
  // xpc_dictionary_set_bool(plist, CSTR('EnableTransactions'), 0);
  xpc_dictionary_set_string(plist, CSTR('CFBundleIdentifier'), CSTR(bundleId));

  const program = CSTR(app.bundleURL().path() + '/' + app.bundleExecutable());
  const args = xpc_array_create_empty();
  xpc_array_append_value(args, xpc_string_create(program));

  xpc_dictionary_set_value(plist, CSTR('ProgramArguments'), args);
  xpc_dictionary_set_string(plist, CSTR('Program'), program);

  // const home = app.bundleContainerURL().path().toString();
  // const env = xpc_dictionary_create_empty();
  // {
  //   xpc_dictionary_set_string(env, CSTR('HOME'), CSTR(home));
  //   xpc_dictionary_set_string(env, CSTR('TMPDIR'), CSTR(home + '/tmp'));
  //   xpc_dictionary_set_string(env, CSTR('CFFIXED_USER_HOME'), CSTR(home));
  //   xpc_dictionary_set_string(env, CSTR('SHELL'), CSTR('/bin/sh'));
  // }

  // xpc_dictionary_set_value(plist, CSTR('EnvironmentVariables'), env);
  // xpc_dictionary_set_value(plist, CSTR('MachServices'), xpc_dictionary_create_empty());

  xpc_dictionary_set_string(plist, CSTR('_ManagedBy'), CSTR('com.apple.runningboard'));

  const label = CSTR(`UIKitApplication:${bundleId}[${Math.random().toString(16).substring(2, 8)}][rb-legacy]`);
  xpc_dictionary_set_string(plist, CSTR('Label'), label);

  // xpc_dictionary_set_int64(plist, CSTR('ExitTimeOut'), 1);
  // xpc_dictionary_set_int64(plist, CSTR('InitialTaskRole'), 1);
  // xpc_dictionary_set_bool(plist, CSTR('MaterializeDatalessFiles'), 1);

  // hack jetsam
  const jetsam = xpc_dictionary_create_empty();
  {
    xpc_dictionary_set_int64(jetsam, CSTR('JetsamPriority'), 14);
    xpc_dictionary_set_int64(jetsam, CSTR('ActiveHardMemoryLimit'), 50);
    xpc_dictionary_set_int64(jetsam, CSTR('InactiveHardMemoryLimit'), 50);
  }
  xpc_dictionary_set_value(plist, CSTR('JetsamProperties'), jetsam);
  // xpc_dictionary_set_bool(plist, CSTR('WaitForDebugger'), 1);
  //  

  // console.log(xpcDescription(plist));

  return submit(plist);
}

// jsdoc for EXtensionInfo

/**
 * @typedef ExtensionInfo
 * @property {string} id
 * @property {string} path
 * @property {string} exec
 * @property {string} abs
 */

/**
 * @param {string} bundleId bundle id of host app
 * @returns {ExtensionInfo[]} list of extensions
 */
rpc.exports.extensions = function (bundleId) {
  const app = getApp(bundleId);

  function* gen() {
    const plugins = app.plugInKitPlugins();
    for (let i = 0; i < plugins.count(); i++) {
      const plugin = plugins.objectAtIndex_(i);
      const plist = plugin.infoPlist();

      const exec = plist.objectForKey_('CFBundleExecutable').toString()
      const path = plist.objectForKey_('Path').toString();
      const abs = path + '/' + exec;
      const id = plugin.bundleIdentifier().toString();
      yield { id, path, exec, abs };
    }
  }

  return [...gen()];
}

/**
 * get main executable of app
 * @param {string} bundleId 
 * @returns {string}
 */
rpc.exports.main = function (bundleId) {
  return getApp(bundleId).bundleExecutable().toString();
}

// hand test
// console.log(rpc.exports.spawn('com.apple.Preferences'));
// console.log(rpc.exports.kickstart('com.apple.reminders.sharingextension'));
// console.log(JSON.stringify(rpc.exports.extensions('ph.telegra.Telegraph')));
// console.log(rpc.exports.main('ph.telegra.Telegraph'));
