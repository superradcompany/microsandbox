# microsandbox-binaries

`microsandbox-binaries` is the optional runtime companion for the
[`microsandbox`](../ruby) Ruby SDK. Its platform gems contain the `msb`
executable and libkrunfw firmware library used by local sandboxes. Most users
should install `microsandbox`; install this companion only when local runtime
support is needed:

```sh
gem install microsandbox-binaries
```

The main gem discovers this gem opportunistically and has no dependency on it,
so cloud-only installations do not download runtime binaries. Explicit
`MSB_PATH` and `MSB_LIBKRUNFW_PATH` environment variables retain precedence
over the bundled files.

Runtime files are downloaded from the matching Microsandbox GitHub release and
packaged as pure data for `arm64-darwin`, `x86_64-linux-gnu`, and
`aarch64-linux-gnu`. There is no generic `ruby`-platform fallback gem.
