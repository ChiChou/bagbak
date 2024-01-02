const chmod = new NativeFunction(Module.findExportByName(null, 'chmod'), 'int', ['pointer', 'int']);
const stat = new NativeFunction(Module.findExportByName(null, 'stat'), 'int', ['pointer', 'pointer']);

rpc.exports.chmod = function (path) {
  const buf = Memory.alloc(0x100);
  const ret = stat(Memory.allocUtf8String(path), buf);
  // get current mode and set executable bit
  if (ret !== 0) throw new Error('stat failed');
  let mode = buf.readU32();
  mode |= 0o111;
  return chmod(Memory.allocUtf8String(path), mode);
}
