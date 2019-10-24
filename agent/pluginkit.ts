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