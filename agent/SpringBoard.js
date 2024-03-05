Module.load('/usr/lib/system/libxpc.dylib');
const libxpc = Process.findModuleByName('libxpc.dylib');

if (!ObjC.available) throw new Error('invalid runtime');

const xpc_dictionary_create_empty = new NativeFunction(libxpc.findExportByName('xpc_dictionary_create_empty'), 'pointer', []);
const xpc_dictionary_set_uint64 = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_uint64'), 'void', ['pointer', 'pointer', 'uint64']);
const xpc_dictionary_set_string = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_string'), 'void', ['pointer', 'pointer', 'pointer']);
const xpc_dictionary_set_value = new NativeFunction(libxpc.findExportByName('xpc_dictionary_set_value'), 'void', ['pointer', 'pointer', 'pointer']);

const xpc_dictionary_get_value = new NativeFunction(libxpc.findExportByName('xpc_dictionary_get_value'), 'pointer', ['pointer', 'pointer']);
const xpc_dictionary_get_int64 = new NativeFunction(libxpc.findExportByName('xpc_dictionary_get_int64'), 'int64', ['pointer', 'pointer']);

const xpc_array_create_empty = new NativeFunction(libxpc.findExportByName('xpc_array_create_empty'), 'pointer', []);
const xpc_array_append_value = new NativeFunction(libxpc.findExportByName('xpc_array_append_value'), 'void', ['pointer', 'pointer']);
const xpc_array_get_int64 = new NativeFunction(libxpc.findExportByName('xpc_array_get_int64'), 'int64', ['pointer', 'size_t']);

const xpc_string_create = new NativeFunction(libxpc.findExportByName('xpc_string_create'), 'pointer', ['pointer']);
const xpc_uuid_create = new NativeFunction(libxpc.findExportByName('xpc_uuid_create'), 'pointer', ['pointer']);

const xpc_connection_resume = new NativeFunction(libxpc.findExportByName('xpc_connection_resume'), 'void', ['pointer']);
const xpc_connection_send_message_with_reply = new NativeFunction(libxpc.findExportByName('xpc_connection_send_message_with_reply'), 'pointer', ['pointer', 'pointer', 'pointer', 'pointer']);
const xpc_connection_create_mach_service = new NativeFunction(libxpc.findExportByName('xpc_connection_create_mach_service'), 'pointer', ['pointer', 'pointer', 'uint64']);
const xpc_connection_set_event_handler = new NativeFunction(libxpc.findExportByName('xpc_connection_set_event_handler'), 'void', ['pointer', 'pointer']);

/**
 * @param {pointer} obj 
 * @returns {string}
 */
function xpcDescription(obj) {
  const xpc_copy_description = new NativeFunction(libxpc.findExportByName('xpc_copy_description'), 'pointer', ['pointer']);
  const free = new NativeFunction(Module.findExportByName(null, 'free'), 'void', ['pointer']);

  const desc = xpc_copy_description(obj);
  const result = desc.readUtf8String();
  free(desc);
  return result;
}

// sample request to pkd
//
// <OS_xpc_dictionary: <dictionary: 0x156a27460> { count = 6, transaction: 1, voucher = 0x155efaca0, contents =
// 	"request" => <string: 0x155efbc90> { length = 5, contents = "ready" }
// 	"paths" => <array: 0x155efddf0> { count = 1, capacity = 1, contents =
// 		0: <string: 0x155efd350> { length = 119, contents = "Weather.app/PlugIns/WeatherWidget.appex" }
// 	}
// 	"flags" => <uint64: 0xb229392cae987a37>: 0
// 	"oneshotuuids" => <array: 0x155e58ca0> { count = 1, capacity = 1, contents =
// 		0: <uuid: 0x155efde50> 00000000-0000-0000-0000-000000000000
// 	}
// 	"uuids" => <array: 0x155efe0a0> { count = 1, capacity = 1, contents =
// 		0: <uuid: 0x155e58990> AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA
// 	}
// 	"version" => <uint64: 0xb229392cae987a2f>: 3
// }>

ObjC.classes.NSBundle.bundleWithPath_('/System/Library/Frameworks/CoreServices.framework').load();

/**
 * @param {string} pluginIdentifier 
 * @returns {Promise<Int64>}
 */
rpc.exports.run = function (pluginIdentifier) {
  return new Promise((resolve, reject) => {
    ObjC.schedule(ObjC.mainQueue, () => {
      const conn = xpc_connection_create_mach_service(Memory.allocUtf8String('com.apple.pluginkit.pkd'), NULL, 0);
      xpc_connection_set_event_handler(conn, new ObjC.Block({
        retType: 'void',
        argTypes: ['pointer'],
        implementation(message) {
          // console.log('xpc event:', xpcDescription(message));
        }
      }));
      xpc_connection_resume(conn);

      const plugin = ObjC.classes.LSBundleProxy.bundleProxyForIdentifier_(pluginIdentifier);
      const pluginUUIDString = plugin.pluginUUID().toString();
      const bundleURL = plugin.bundleURL().path().toString();

      const dict = xpc_dictionary_create_empty();
      xpc_dictionary_set_string(dict, Memory.allocUtf8String('request'), Memory.allocUtf8String('ready'));

      const paths = xpc_array_create_empty();
      const path0 = xpc_string_create(Memory.allocUtf8String(bundleURL));
      xpc_array_append_value(paths, path0);
      xpc_dictionary_set_value(dict, Memory.allocUtf8String('paths'), paths);
      xpc_dictionary_set_uint64(dict, Memory.allocUtf8String('flags'), 0);

      const oneshotuuids = xpc_array_create_empty();
      const emptyUUID = Memory.alloc(16);
      emptyUUID.writeByteArray(new Array(16).fill(0));
      const oneshotuuid0 = xpc_uuid_create(emptyUUID);
      xpc_array_append_value(oneshotuuids, oneshotuuid0);
      xpc_dictionary_set_value(dict, Memory.allocUtf8String('oneshotuuids'), oneshotuuids);

      const uuids = xpc_array_create_empty();
      const uuidBinary = Memory.alloc(16);
      plugin.pluginUUID().getUUIDBytes_(uuidBinary);
      const uuid0 = xpc_uuid_create(uuidBinary);
      xpc_array_append_value(uuids, uuid0);

      xpc_dictionary_set_value(dict, Memory.allocUtf8String('uuids'), uuids);
      xpc_dictionary_set_uint64(dict, Memory.allocUtf8String('version'), 3);

      // console.log('request:', xpcDescription(dict));
      xpc_connection_send_message_with_reply(conn, dict, NULL, new ObjC.Block({
        retType: 'void',
        argTypes: ['pointer'],
        implementation(reply) {
          // console.log('reply:', xpcDescription(reply));

          if (!xpc_dictionary_get_value(reply, Memory.allocUtf8String('error')).isNull())
            return reject(new Error(`unexpected error returned from pkd ${xpcDescription(reply)}`));

          const pids = xpc_dictionary_get_value(reply, Memory.allocUtf8String('pids'));
          if (!pids.isNull())
            return resolve(xpc_dictionary_get_int64(pids, Memory.allocUtf8String(pluginUUIDString)).toNumber());
        
          const pidarray = xpc_dictionary_get_value(reply, Memory.allocUtf8String('pidarray'));
          if (!pidarray.isNull())
            return resolve(xpc_array_get_int64(pidarray, 0).toNumber());

          reject(new Error(`unknown schema for XPC reply: ${xpcDescription(reply)}`));
        }
      }));
    });
  });
};

/**
 * @param {string} parentBundle 
 */
rpc.exports.plugins = function (parentBundle) {
  const app = ObjC.classes.LSApplicationProxy.bundleProxyForIdentifier_(parentBundle)
  const plugins = app.plugInKitPlugins();
  if (!plugins) return [];

  function* gen() {
    for (let i = 0; i < plugins.count(); i++) {
      const plugin = plugins.objectAtIndex_(i);
      yield plugin.pluginIdentifier().toString();
    }
  }

  return Array.from(gen());
}
