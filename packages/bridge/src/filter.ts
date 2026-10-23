const NOISE_SYMBOLS = new Set([
  '_start',
  '__start',
  '_init',
  '_fini',
  '__libc_csu_init',
  '__libc_csu_fini',
  '__libc_start_main',
  'deregister_tm_clones',
  'register_tm_clones',
  '__do_global_dtors_aux',
  'frame_dummy',
  '__dyld_private',
  'dyld_stub_binder',
  '_mh_execute_header',
  '__gmon_start__',
  '__cxa_finalize',
  '__stack_chk_fail',
]);

const NOISE_PREFIXES = [
  '__dyld_',
  '__pthread_',
  '__darwin_',
  '__llvm_',
  '__gxx_',
  '__stub_helper',
];

export function isNoiseSymbol(symbolName: string): boolean {
  if (NOISE_SYMBOLS.has(symbolName)) return true;
  for (const prefix of NOISE_PREFIXES) {
    if (symbolName.startsWith(prefix)) return true;
  }
  return false;
}
