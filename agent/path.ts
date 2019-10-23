const SEP = '/'

export function relativeTo(base: string, full: string) {
  const a = normalize(base).split(SEP);
  const b = normalize(full).split(SEP);

  let i = 0;
  while (a[i] === b[i]) i++;
  return b.slice(i).join(SEP);
}

export function normalize(path: string) {
  return ObjC.classes.NSString
    .stringWithString_(path).stringByStandardizingPath().toString();
}
