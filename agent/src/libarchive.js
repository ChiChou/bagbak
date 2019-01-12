const specs = {
  archive_write_set_format_zip: ['int', ['pointer']],
  archive_write_new: ['pointer', []],
  archive_write_open_filename: ['int', ['pointer', 'pointer']],
  archive_entry_new: ['pointer', []],
  archive_entry_set_size: ['int', ['pointer', 'uint']],
  archive_entry_set_filetype: ['int', ['pointer', 'int']],
  archive_entry_set_perm: ['int', ['pointer', 'int']],
  archive_entry_set_pathname: ['int', ['pointer', 'pointer']],
  archive_entry_set_ctime: ['int', ['pointer', 'long', 'long']],
  archive_entry_set_mtime: ['int', ['pointer', 'long', 'long']],
  archive_write_header: ['int', ['pointer', 'pointer']],
  archive_write_data: ['int', ['pointer', 'pointer', 'uint']],
  archive_write_finish_entry: ['int', ['pointer']],
  archive_entry_free: ['int', ['pointer']],
  archive_write_finish: ['int', ['pointer']],
}

/*
  archive_write_finish() This is a deprecated synonym for archive_write_free().
  but libarchive on *OS doesn't seem to have archive_write_free()
*/

const camelCase = name => name.replace(/_([a-z])/g, g => g[1].toUpperCase());
const libarchive = Process.enumerateModulesSync().filter(mod =>
  mod.name.startsWith('libarchive.')).pop().name

for (let [name, signature] of Object.entries(specs)) {
  const mangled = camelCase(name.substr('archive_'.length))
  const p = Module.findExportByName(libarchive, name)
  const [retType, argTypes] = signature
  module.exports[mangled] = new NativeFunction(p, retType, argTypes)
}
