
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


export function launch(id: string) {
  const { NSExtension, NSString } = ObjC.classes;

  const identifier = NSString.stringWithString_(id);
  const extension = NSExtension.extensionWithIdentifier_error_(identifier, NULL);
  identifier.release();
  if (!extension)
    return Promise.reject(new Error(`unable to create extension ${id}`));

  const pid = extension['- _plugInProcessIdentifier']();
  if (pid)
    return Promise.resolve(pid);

  return new Promise((resolve, reject) => {
    extension.beginExtensionRequestWithInputItems_completion_(NULL, new ObjC.Block({
      retType: 'void',
      argTypes: ['object'],
      implementation(requestIdentifier) {
        const pid = extension.pidForRequestIdentifier_(requestIdentifier);
        extension.release();
        resolve(pid);
      }
    }))
  })
}

/*
  -[NSExtension _newExtensionContextAndGetConnection:assertion:inputItems:]

  v8 = _objc_msgSend((void *)self->_infoDictionary, "objectForKey:", CFSTR("NSExtension"));
  v9 = _objc_msgSend(v8, "objectForKey:", CFSTR("NSExtensionContextHostClass"));
  if ( v9
    || (v9 = _objc_msgSend((void *)self->_infoDictionary, "objectForKey:", CFSTR("NSExtensionContextHostClass"))) != 0LL )
  {
    v10 = v6;
    v11 = _objc_msgSend(v9, "UTF8String");
    v12 = (void *)objc_getClass(v11);
  }
  else
  {
    v10 = v6;
    v12 = _objc_msgSend(&OBJC_CLASS___NSExtensionContext, "class");
  }

  if the given class does not exist, a nil ptr exception will throw
 */
const baseClazz = Memory.allocUtf8String('NSExtensionContext')
Interceptor.attach(Module.findExportByName(null, 'objc_getClass')!, {
  onEnter(args) {
    const clz: string = args[0].readUtf8String()!
    if (clz.endsWith('ExtensionHostContext'))
      args[0] = baseClazz
  }
})

export function launchAll() {
  return Promise.all(plugins().map(id => launch(id)));
}