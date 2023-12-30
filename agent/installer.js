const chmod = new NativeFunction(Module.findExportByName(null, 'chmod'), 'int', ['pointer', 'int']);

rpc.exports.chmod = function (path, mode) {
  return chmod(Memory.allocUtf8String(path), mode);
}
