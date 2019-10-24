export function jetsam(pid: number) {
  const MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT = 6;
  const p = Module.findExportByName(null, 'memorystatus_control')!;
  const memctl = new NativeFunction(p, 'int', ['uint32', 'int32', 'uint32', 'pointer', 'uint32']);
  return memctl(MEMORYSTATUS_CMD_SET_JETSAM_TASK_LIMIT, pid, 256, NULL, 0);
}

export function skipPkdValidationFor(pid: number) {
  if ('PKDPlugIn' in ObjC.classes) {
    const method = ObjC.classes.PKDPlugIn['- allowForClient:'];
    const original = method.implementation;
    method.implementation = ObjC.implement(method, function(self, sel, conn) {
      // race condition huh? we don't care
      return pid === new ObjC.Object(conn).pid() ?
        NULL : original(self, sel, conn);
    })
  }
}