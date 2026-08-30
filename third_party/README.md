# Patched msb_krun crates

Copies of the published `msb_krun`, `msb_krun_devices` and `msb_krun_utils`
0.1.32 crates (zerocore-ai/libkrun @ dc9f5f1) with the changes the experimental
virtio-gpu display (`MSB_GPU`, `msb display`) needs, applied through
`[patch.crates-io]` until they land upstream:

- `msb_krun`: `ConsoleBuilder::gpu_display`, `gpu_display_backend`,
  `input_device`; re-exports `krun_display` and `krun_input`.
- `msb_krun_devices`: the virtio-gpu runs on rutabaga's 2D component when
  virgl is off (`NO_VIRGL` without `VENUS`), advertises no virgl/blob/context
  features, and copies only the scanout rectangle on flush instead of
  panicking on a size mismatch.
- `msb_krun_utils`: the macOS pipe-based `EventFd` honours `EFD_NONBLOCK`
  when combined with `EFD_SEMAPHORE` (virtio-input never delivered events
  otherwise).

Each change is one commit on top of the published crate in the patch
repositories this tree was copied from; `git log -p` there is the PR.
