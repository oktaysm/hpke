project(
    'hpke',
    'c',
    version : '0.1',
    default_options : ['c_std=gnu99'],
)

pkg = import('pkgconfig')

crypto_dep = dependency('libcrypto')

inc = include_directories('src')

lib_src = [
    'src/hpke/aead.c',
    'src/hpke/hkdf.c',
    'src/hpke/kem.c',
    'src/hpke/hpke.c',
]

lib = library(
    'hpke',
    include_directories : inc,
    sources: [lib_src],
    dependencies: [crypto_dep],
    gnu_symbol_visibility: 'hidden',
    install: true 
)

exe = executable(
    'exe',
    include_directories : inc,
    sources : ['src/hpke/test.c', lib_src],
    dependencies: [crypto_dep],
    install: false
)

test('exe', exe, verbose : true)

pkg.generate(lib)

install_headers('src/hpke/hpke.h', subdir: 'hpke')