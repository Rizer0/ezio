# ezio
![demo](ezio.jpg)

Minimal, dependency-light helpers for socket/process I/O and inline assembly—built to speed up **Windows binary exploitation** practice without the tedium of re-writing sockets and boilerplate every time.

> Motivation: I made this to practice Windows binary exploitation without getting bored of writing sockets and doing everything manually. Written fully in one day. So, there might be a lot of issues, you can report any issues or help making improvments at any time.

## Features

- **Remote TCP I/O**: `remote(host, port, timeout)` with `send`, `sendline`, `recv`, `recvuntil`, `recvline`, and context-manager support.
- **Local process I/O**: `process(path_or_argv)` to interact with local EXEs via stdin/stdout (recv/send style).
- **Pack/Unpack**: `p8/p16/p32/p64` and `u8/u16/u32/u64` (little-endian) using `struct`.
- **flat()**: Concatenate bytes/strings/ints; ints are packed LE by `word_size` (2/4/8).
- **Assembler**: `assemble()` powered by Keystone with configurable context (`arch`, `bits`, `syntax`).
- **QoL**: `pause()` and `sleep()`.

## Install

```bash
pip install -r requirements.txt
```

Place `ezio.py` somewhere on your `PYTHONPATH`, or next to your scripts.

## Quick Examples

### 1) Remote TCP (send payload)

```python
from ezio import remote, flat, p32

jmp_esp = p32(0x148010cf)
offset  = 2288
payload = flat(b"\x90" * offset, jmp_esp)

print("Sending evil buffer...")
with remote("127.0.0.1", 3344, timeout=1.0) as io:
    io.send(payload)
print("Done!")
```

### 2) Local Process (Windows EXE)

```python
from ezio import process

io = process(r".\welcome.exe")
io.recvuntil(b"name:")
io.sendline(b"Nullbyte0x")
print(io.recvline().decode("utf-8", "ignore"))
io.close()
```

### 3) Assemble Inline ASM

Use a global context:

```python
from ezio import assemble, set_asm_context

set_asm_context(arch="x86", bits=32, syntax="intel")
sc = assemble("nop; jmp 0x04")
```

Or per-call:

```python
from ezio import assemble
sc = assemble("jmp 0x04", arch="x86", bits=32, syntax="intel")
```

### 4) Full exploit-style snippet using your pattern

```python
from ezio import remote, p32, assemble

jmp_esp = p32(0x148010cf)
offset  = 2288
sled    = assemble("times 80 nop")  # if you added a helper; else: b"\x90"*80
shortj  = assemble("jmp 0xdeadbeef")

payload = b"\x41"*offset + jmp_esp + sled + shortj

io = remote("127.0.0.1", 1337, timeout=3.0)
io.send(payload)
io.close()
```

## API (Core)

### Sockets
- `remote(host: str, port: int, timeout: float | None = 5.0) -> Remote`
  - Methods: `send(b)`, `sendline(b=b"")`, `recv(n=4096)`, `recvuntil(delim, max_bytes=None)`, `recvline(keepends=True, max_bytes=None)`, `close()`
  - Context manager: `with remote(...) as io: ...`

### Processes
- `process(args: str | list[str], timeout: float | None = 5.0) -> Process`
  - Methods: `send`, `sendline`, `recv`, `recvuntil`, `recvline`, `close`
  - Property: `alive`

### Packing/Unpacking
- `p8/p16/p32/p64(int) -> bytes` (LE)
- `u8/u16/u32/u64(bytes) -> int` (LE)
- `flat(*items, word_size=4) -> bytes`

### Assembler
- `assemble(src, arch="x86", bits=32, syntax="intel") -> bytes`
- `set_asm_context(arch="x86", bits=32, syntax="intel") -> None`  
  Requires `keystone-engine`.

### Utilities
- `pause(msg: str = "[paused] press Enter to continue...")`
- `sleep(sec: float)`

## Requirements

- Python 3.8+
- `keystone-engine` (for `assemble()`)

## Disclaimer

For educational and lawful testing only. Use strictly on targets you own or have permission to test.
