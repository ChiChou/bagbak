let targetPid = -1;

const { PKDPlugIn } = ObjC.classes;

if (!PKDPlugIn) {
  console.error('Warning: PKDPlugIn class not found');
} else {
  const canidates = ['- allowForClient:discoveryInstanceUUID:', '- allowForClient:'];
  for (const name of canidates) {
    const method = PKDPlugIn[name];
    if (method) {
      const original = method.implementation;
      method.implementation = ObjC.implement(method, function (self, sel, conn) {
        return targetPid === new ObjC.Object(conn).pid() ?
          NULL : original(self, sel, conn);
      })
      break;
    }
  }
}


/**
 * skip PKD validation for the given pid
 * @param {number} pid 
 */
rpc.exports.skipPkdValidationFor = (pid) => {
  targetPid = pid;
}
