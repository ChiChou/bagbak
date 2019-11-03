/**
 * 
 * @param {Error} err 
 */
function usage(err) {
  console.error(err.message)
  console.log(`Usage: node go.js [--uuid] [--host] app
    uuid: uuid of connected USB device
    host: hostname of remote device (via TCP)
    app: bundle id or name
  `)
  
}

/**
 * 
 * @param {Array} args 
 * @returns {Object} options
 */
function parse(args) {
  const dict = {
    app: null,
    uuid: null,
    host: null,
    help: false,
  }

  const capital = {}
  for (let key of Object.keys(dict)) {
    capital[key.toUpperCase().substr(0, 1)] = key
  }

  let key = undefined
  for (let str of args) {
    let current = undefined
    let valid = false

    if (str.startsWith('--')) {
      current = str.substr(2).toLowerCase()
      valid = current in dict
    } else if (str.startsWith('-')) {
      const alphabet = str.toUpperCase().substr(1)
      valid = alphabet in capital
      current = capital[alphabet]
    } else if (key) {
      dict[key] = str
      key = undefined
      continue
    }

    if (current && valid) {
      if (key)
        throw new Error(`${key} requires a value`)

      key = current
      continue
    }
    
    if (!dict.app)
      dict.app = str
    else
      throw new Error(`Unknown option "${str}"`)
  }
  
  if (!dict.app) {
    throw new Error('requires app name')
  }

  return dict
}

module.exports = {
  parse,
  usage,
}

// process.argv.slice(2)
// try {
//   console.log(1, parse(['--host', '192.168.1.1', '-U', 'bar', 'WordPress']))
//   console.log(2, parse(['--foo', 'bar']))
// } catch(e) {
//   usage(e)
// }
