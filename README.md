# K-SHELL

Deterministic bootstrap chain for K-UX/π:

- `k_shell.c` = Stage-0 genesis generator.
- `k_shell_v2.c` = Stage-2 self-hosting bootstrap anchor.

## Stage-0 (genesis)

```bash
gcc k_shell.c -O2 -static -o k_shell
./k_shell
```

Emits deterministic Stage-1 artifacts:

- `sha256.h`
- `sha256.c`
- `kux_verifier.c`
- `build.bat`

## Stage-2 (self-hosting anchor)

```bash
gcc k_shell_v2.c -O2 -static -o k_shell_v2
./k_shell_v2 --verify
./k_shell_v2
```

Stage-2 behavior:

- verifies `k_shell_v2.c` before emission (unless `--force`)
- re-emits Stage-1 files and `verify_bootstrap.bat`
- re-emits `k_shell_v2.c` byte-for-byte from on-disk source
- prints bootstrap anchor SHA256

## Bootstrap chain check

Use `verify_bootstrap.bat` to check Stage-0/1/2 presence and run Stage-2 self-verification on Windows.
