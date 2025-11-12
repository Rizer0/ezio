import socket, struct, subprocess, threading, time, re
from typing import Optional, Union, Iterable, Tuple, List
try:
    from keystone import (
        Ks, KsError,
        KS_ARCH_X86, KS_MODE_16, KS_MODE_32, KS_MODE_64,
        KS_OPT_SYNTAX_INTEL, KS_OPT_SYNTAX_ATT
    )
except Exception as e:
    raise ImportError("keystone-engine is required for assemble(). pip install keystone-engine") from e

BytesLike = Union[bytes, bytearray, memoryview]

def p16(x:int)->bytes: return struct.pack("<H", x & 0xFFFF)
def p32(x:int)->bytes: return struct.pack("<I", x & 0xFFFFFFFF)
def p64(x:int)->bytes: return struct.pack("<Q", x & 0xFFFFFFFFFFFFFFFF)

def u16(b:BytesLike)->int: return struct.unpack("<H", bytes(b))[0]
def u32(b:BytesLike)->int: return struct.unpack("<I", bytes(b))[0]
def u64(b:BytesLike)->int: return struct.unpack("<Q", bytes(b))[0]

def flat(*items: Iterable[Union[int,str,BytesLike]], word_size:int=4)->bytes:
    out=bytearray()
    pk={2:p16,4:p32,8:p64}.get(word_size)
    if pk is None: raise ValueError("word_size must be 2,4,8")
    for it in items:
        if isinstance(it,int): out+=pk(it)
        elif isinstance(it,(bytes,bytearray,memoryview)): out+=bytes(it)
        elif isinstance(it,str): out+=it.encode("ascii")
        else: raise TypeError(f"Unsupported type: {type(it)}")
    return bytes(out)

class Remote:
    def __init__(self, host:str, port:int, timeout:Optional[float]=5.0):
        self.host=host; self.port=port; self.timeout=timeout; self._sock:Optional[socket.socket]=None
        self.connect()
    def __enter__(self): return self
    def __exit__(self, a,b,c): self.close()
    @property
    def connected(self)->bool: return self._sock is not None
    def connect(self)->None:
        if self._sock is not None: return
        s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        if self.timeout is not None: s.settimeout(self.timeout)
        s.connect((self.host,self.port))
        self._sock=s
    def close(self)->None:
        if self._sock is not None:
            try: self._sock.shutdown(socket.SHUT_RDWR)
            except OSError: pass
            try: self._sock.close()
            finally: self._sock=None
    def send(self,data:BytesLike)->int:
        if self._sock is None: raise RuntimeError("Socket is closed")
        self._sock.sendall(data); return len(data)
    def sendline(self,data:BytesLike=b"")->int:
        return self.send(bytes(data)+b"\n")
    def recv(self,n:int=4096)->bytes:
        if self._sock is None: raise RuntimeError("Socket is closed")
        sock=self._sock
        original_to=sock.gettimeout()
        deadline=None if self.timeout is None else time.time()+self.timeout
        idle=0.03
        buf=bytearray()
        try:
            while True:
                if deadline is None:
                    per=idle
                else:
                    rem=deadline-time.time()
                    if rem<=0: break
                    per=min(idle, max(rem, 0))
                try:
                    sock.settimeout(per)
                except Exception:
                    pass
                want=4096
                try:
                    chunk=sock.recv(want)
                    if not chunk:
                        break
                    buf+=chunk
                    if n>0 and len(buf)>=n:
                        break
                except socket.timeout:
                    break
        finally:
            try:
                sock.settimeout(original_to)
            except Exception:
                pass
        if n>0:
            return bytes(buf[:n])
        return bytes(buf)
    def recvuntil(self,delim:BytesLike,max_bytes:Optional[int]=None)->bytes:
        if self._sock is None: raise RuntimeError("Socket is closed")
        d=bytes(delim); buf=bytearray()
        while True:
            c=self._sock.recv(1)
            if not c: break
            buf+=c
            if buf.endswith(d): break
            if max_bytes is not None and len(buf)>=max_bytes: break
        return bytes(buf)
    def recvline(self,keepends:bool=True,max_bytes:Optional[int]=None)->bytes:
        line=self.recvuntil(b"\n",max_bytes=max_bytes)
        if not keepends and line.endswith(b"\n"): return line[:-1]
        return line

def remote(host:str,port:int,timeout:Optional[float]=5.0)->Remote:
    return Remote(host,port,timeout)

class Process:
    def __init__(self, args:Union[str,List[str]], timeout:Optional[float]=5.0):
        self.timeout=timeout
        self._p=subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0)
        self._buf=bytearray()
        self._eof=False
        self._lock=threading.Lock()
        self._cv=threading.Condition(self._lock)
        self._t=threading.Thread(target=self._reader,daemon=True); self._t.start()
    def __enter__(self): return self
    def __exit__(self,a,b,c): self.close()
    @property
    def alive(self)->bool:
        return self._p.poll() is None
    def _reader(self):
        try:
            while True:
                b=self._p.stdout.read(1)
                if not b: break
                with self._cv:
                    self._buf+=b
                    self._cv.notify_all()
        finally:
            with self._cv:
                self._eof=True
                self._cv.notify_all()
    def send(self,data:BytesLike)->int:
        if self._p.stdin is None: raise RuntimeError("stdin is closed")
        self._p.stdin.write(bytes(data)); self._p.stdin.flush(); return len(data)
    def sendline(self,data:BytesLike=b"")->int:
        return self.send(bytes(data)+b"\n")
    def _wait_for(self, want:int=1, timeout:Optional[float]=None)->bool:
        end=None if timeout is None else time.time()+timeout
        with self._cv:
            while len(self._buf)<want and not self._eof:
                if end is None:
                    self._cv.wait()
                else:
                    rem=end-time.time()
                    if rem<=0: break
                    self._cv.wait(rem)
            return len(self._buf)>=want
    def recv(self,n:int=4096, timeout:Optional[float]=None)->bytes:
        eff_timeout = self.timeout if timeout is None else timeout
        self._wait_for(1, eff_timeout)
        idle=0.03
        deadline=None if eff_timeout is None else time.time()+eff_timeout
        with self._cv:
            last_len=-1
            while True:
                cur_len=len(self._buf)
                if cur_len==0 and self._eof:
                    break
                if cur_len==last_len:
                    if deadline is not None:
                        rem=deadline-time.time()
                        if rem<=0:
                            break
                        self._cv.wait(min(idle, max(rem,0)))
                    else:
                        self._cv.wait(idle)
                    if len(self._buf)==cur_len:
                        break
                    else:
                        last_len=-1
                        continue
                else:
                    last_len=cur_len
                    if deadline is not None:
                        rem=deadline-time.time()
                        if rem<=0:
                            break
                        self._cv.wait(min(idle, max(rem,0)))
                    else:
                        self._cv.wait(idle)
            if n<=0:
                out=bytes(self._buf)
                self._buf.clear()
                return out
            out=bytes(self._buf[:n])
            del self._buf[:len(out)]
            return out
    def recvuntil(self,delim:BytesLike, max_bytes:Optional[int]=None, timeout:Optional[float]=None)->bytes:
        d=bytes(delim)
        end=None if (timeout if timeout is not None else self.timeout) is None else time.time()+(timeout if timeout is not None else self.timeout)
        while True:
            with self._cv:
                i=self._buf.find(d)
                if i!=-1:
                    i_end=i+len(d)
                    out=bytes(self._buf[:i_end]); del self._buf[:i_end]; return out
                if max_bytes is not None and len(self._buf)>=max_bytes:
                    out=bytes(self._buf[:max_bytes]); del self._buf[:max_bytes]; return out
                if self._eof:
                    out=bytes(self._buf); self._buf.clear(); return out
                if end is not None:
                    rem=end-time.time()
                    if rem<=0:
                        out=bytes(self._buf); self._buf.clear(); return out
                    self._cv.wait(rem)
                else:
                    self._cv.wait()
    def recvline(self, keepends:bool=True, timeout:Optional[float]=None, max_bytes:Optional[int]=None)->bytes:
        line=self.recvuntil(b"\n", max_bytes=max_bytes, timeout=timeout)
        if not keepends and line.endswith(b"\n"): return line[:-1]
        return line
    def close(self):
        try:
            if self._p.stdin: 
                try: self._p.stdin.close()
                except Exception: pass
            if self._p.stdout:
                try: self._p.stdout.close()
                except Exception: pass
            if self._p.stderr:
                try: self._p.stderr.close()
                except Exception: pass
            if self.alive:
                try: self._p.terminate()
                except Exception: pass
        finally:
            try:
                self._p.wait(timeout=0.2)
            except Exception:
                try:
                    self._p.kill()
                except Exception: pass

def process(args:Union[str,List[str]], timeout:Optional[float]=5.0)->Process:
    return Process(args, timeout)

def pause(msg: str = "[paused] press Enter to continue..."):
    try:
        input(msg)
    except EOFError:
        pass

def sleep(sec: float):
    time.sleep(sec)

class Asm:
    def __init__(self, arch: str = "x86", bits: int = 32, syntax: str = "intel"):
        self._arch = None
        self._mode = None
        self._syntax = None
        self.set_context(arch, bits, syntax)

    def set_context(self, arch: str = "x86", bits: int = 32, syntax: str = "intel"):
        arch = arch.lower()
        syntax = syntax.lower()

        if arch != "x86":
            raise ValueError("Only x86/x86_64 supported. Use arch='x86' with bits=16/32/64.")
        if bits not in (16, 32, 64):
            raise ValueError("bits must be 16, 32, or 64")

        self._arch = KS_ARCH_X86
        self._mode = {16: KS_MODE_16, 32: KS_MODE_32, 64: KS_MODE_64}[bits]
        self._syntax = {"intel": KS_OPT_SYNTAX_INTEL, "att": KS_OPT_SYNTAX_ATT}.get(syntax, KS_OPT_SYNTAX_INTEL)
        return self

    def _parse_imm_token(self, tok: str) -> Optional[int]:

        if not tok:
            return None
        tok = tok.strip()
        if tok.startswith('$'):
            tok = tok[1:]
        tok = tok.strip("() ")
        if not tok:
            return None
        try:
            if tok.lower().startswith("0x") or tok.lower().startswith("-0x"):
                return int(tok, 16)
            return int(tok, 10)
        except ValueError:
            try:
                return int(tok, 0)
            except Exception:
                return None

    def _fallback_encode(self, src: str) -> Optional[bytes]:

        s = src.strip().lower()


        m = re.search(r'(?:\.byte|db|byte)\s+([0-9x,\s\-]+)', s)
        if m:
            parts = [p.strip() for p in m.group(1).split(',') if p.strip()]
            try:
                out = bytes(int(p, 0) & 0xff for p in parts)
                return out
            except Exception:
                pass

        m = re.match(r'jmp\s+short\s+(.+)', s)
        if m:
            imm_tok = m.group(1).strip()
            imm = self._parse_imm_token(imm_tok)
            if imm is None:
                t2 = re.match(r'\$(-?\w+)', imm_tok)
                if t2:
                    imm = self._parse_imm_token(t2.group(1))
            if imm is not None:
                imm8 = imm & 0xff
                return bytes([0xEB, imm8])

        m2 = re.match(r'jmp\s+(0x[0-9a-f]+)$', s)
        if m2:
            return None

        return None

    def assemble(self, src: Union[str, bytes]) -> bytes:
        if isinstance(src, bytes):
            src = src.decode("utf-8", "ignore")
        src = src.strip()
        ks = Ks(self._arch, self._mode)
        ks.syntax = self._syntax
        try:
            enc, _ = ks.asm(src)
            return bytes(enc)
        except KsError as e:
            fb = self._fallback_encode(src)
            if fb is not None:
                return fb
            raise RuntimeError(f"Keystone failed to assemble and fallback couldn't handle it: {e}") from e

_default_asm = Asm()

def assemble(src: Union[str, bytes], arch: Optional[str] = None, bits: Optional[int] = None, syntax: Optional[str] = None) -> bytes:
    if arch or bits or syntax:
        return Asm(arch or "x86", bits or 32, syntax or "intel").assemble(src)
    return _default_asm.assemble(src)

def set_asm_context(arch: str = "x86", bits: int = 32, syntax: str = "intel") -> None:
    _default_asm.set_context(arch, bits, syntax)
