const fsp = require('fs/promises')
const path = require('path')

function file(name) {
  return path.join(__dirname, '..', 'agent', 'cmod', name)
}

async function main() {
  const content = await fsp.readFile(file('source.c'))
  const str = JSON.stringify(content.toString())
  await fsp.writeFile(file('index.ts'), `export default ${str}`)
}

main()