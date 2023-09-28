rpc.exports = {
  /**
   * Determines if running on a rootless jailbreak
   * @returns {boolean} true if rootless, false if rootful
   */
  isRootless() {
    const accessAddr = Module.getExportByName('/usr/lib/system/libsystem_kernel.dylib', 'access');
    const access = new NativeFunction(accessAddr, 'int', ['pointer', 'int']);
    const F_OK = 0;
    const rootlessJBDir = Memory.allocUtf8String('/var/jb/');
    return access(rootlessJBDir, F_OK) == 0;
  }
}