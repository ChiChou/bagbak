interface ThreadsNamespace {
  [key: string]: NativeFunction;
}

const threads: ThreadsNamespace = {}
for (let action of ['suspend', 'resume']) {
  threads[action] = new NativeFunction(Module.findExportByName(
    'libsystem_kernel.dylib', `thread_${action}`)!, 'pointer', ['uint']); 
}

export function freeze() {
  for (let { id } of Process.enumerateThreads())
    threads.suspend(id)
}

export function wakeup() {
  for (let { id } of Process.enumerateThreads())
    threads.resume(id)
}