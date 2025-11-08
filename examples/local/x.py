from ezio import *

io = process(r".\welcome.exe")
print(io.recv())
io.sendline(b"Sam")
out = io.recvline()
print(out.decode("utf-8", "ignore"))

io.close()

