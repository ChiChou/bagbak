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

export function plugins() {
  const {
    LSApplicationWorkspace,
    NSString,
    NSMutableArray,
    NSPredicate,
    NSBundle
  } = ObjC.classes;

  const args = NSMutableArray.alloc().init();
  args.setObject_atIndex_(NSBundle.mainBundle().bundleIdentifier(), 0);
  const fmt = NSString.stringWithString_('containingBundle.applicationIdentifier=%@');
  const predicate = NSPredicate.predicateWithFormat_argumentArray_(fmt, args);
  const plugins = LSApplicationWorkspace.defaultWorkspace()
    .installedPlugins().filteredArrayUsingPredicate_(predicate);
  const result = [];
  for (let i = 0; i < plugins.count(); i++) {
    result.push(plugins.objectAtIndex_(i).pluginIdentifier().toString());
  }
  args.release();
  return result;
}