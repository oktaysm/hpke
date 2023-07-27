HPKE is an implementetion of [RFC-9180](https://www.rfc-editor.org/rfc/rfc9180.html) Hybrid Public Key Encryption API. Depends on LibreSSL libcrypto library.

### Build Example

```shell
pacman -S libressl
```

Make sure to get LibreSSL libraries.

```shell
PKGCONFIG_DIR=/usr/lib/libressl/pkgconfig/
meson setup builddir -Dpkg_config_path=$PKGCONFIG_DIR
cd builddir
ninja test
```

LibreSSL's libcrypto library is not gonna be your default libcrypto library most likely. So you have to specify the directory libcrypto.pc file exist.
