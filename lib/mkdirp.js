const path = require('path')
const fs = require('fs').promises

const _0777 = parseInt('0777', 8) & (~process.umask())

/**
 * @return {Promise<boolean>} made
 */
async function mkdirp(p, mode=_0777) {
  const abs = path.resolve(p)
  try {
    return await fs.mkdir(abs, mode)
  } catch(err) {
    if (err.code === 'ENOENT') {
      return mkdirp(path.dirname(abs), mode).then(() => mkdirp(abs, mode))
    } else {
      const stat = await fs.stat(abs)
      if (!stat.isDirectory())
        throw err
    }
  }
}

module.exports = mkdirp

// async function test() {
//   await mkdirp('/tmp/foo/bar/aaa/bbb')
// }
