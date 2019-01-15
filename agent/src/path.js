const SEP = '/'

export function relativeTo(base, full) {
  const a = normalize(base).split(SEP)
  const b = normalize(full).split(SEP)

  let i = 0;
  while (a[i] === b[i])
    i++
  return b.slice(i).join(SEP)
}

export function normalize(path) {
  return ObjC.classes.NSString.stringWithString_(path)
    .stringByStandardizingPath().toString()
}

export function rstrip(path) {
  return path.replace(/\/$/, '')
}

export function join() {
  return [].map.call(arguments, rstrip).join(SEP)
}

export function basename(path) {
  return ObjC.classes.NSString.stringWithString_(path)
    .lastPathComponent().toString()
}