const POSIX_SPAWN_START_SUSPENDED = 0x0080;

const posix_spawn = new NativeFunction(
  Module.findExportByName(null, 'posix_spawnp'),
  'int',
  ['pointer', 'pointer', 'pointer', 'pointer', 'pointer', 'pointer']);

const posix_spawnattr_init = new NativeFunction(
  Module.findExportByName(null, 'posix_spawnattr_init'),
  'int',
  ['pointer']);

const posix_spawnattr_setflags = new NativeFunction(
  Module.findExportByName(null, 'posix_spawnattr_setflags'),
  'int',
  ['pointer', 'int']);

const waitpid = new NativeFunction(
  Module.findExportByName(null, 'waitpid'),
  'int',
  ['int', 'pointer', 'int']);

rpc.exports = {
  /**
   * spawn a process and suspend it
   * @param {string} path 
   */
  spawn(path) {
    const SIZE = 0x100;
    const attr = Memory.alloc(SIZE);
    const pPid = Memory.alloc(4);

    pPid.writeInt(0);

    const argv = Memory.alloc(Process.pointerSize * 8 * 2);
    const argv0 = Memory.allocUtf8String(path);
    argv.writePointer(argv0);
    argv.add(Process.pointerSize).writePointer(NULL);

    const envp = Memory.alloc(Process.pointerSize * 2);
    envp.writePointer(Memory.allocUtf8String('PATH=/usr/bin:/bin:/usr/sbin:/sbin'));
    envp.add(Process.pointerSize).writePointer(NULL);

    posix_spawnattr_init(attr);
    posix_spawnattr_setflags(attr, POSIX_SPAWN_START_SUSPENDED);
    posix_spawn(pPid, argv0, NULL, attr, argv, envp);

    return pPid.readInt();
  },

  /**
   * cleanup zombie process
   * @param {number} pid of the zombie process
   */
  cleanup(pid) {
    const WNOHANG = 1;
    const status = Memory.alloc(4);
    status.writeInt(0);
    return waitpid(pid, status, WNOHANG) === pid;
  }
}
