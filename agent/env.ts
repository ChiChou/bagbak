export default function() {
  const keys = ['CFFIXED_USER_HOME', 'HOME', 'TMPDIR'];
  const env = ObjC.classes.NSProcessInfo.processInfo().environment();
  const result: {[key: string]: string} = {};
  for (let key of keys) {
    result[key] = env.objectForKey_(key).toString();
  }
  return result;
}
