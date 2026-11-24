# Builds a harmless test binary with planted obfuscated IOCs.
# Usage: python3 tests/make_sample.py out.bin host.exe embed.exe
import base64, sys
base = open(sys.argv[2], 'rb').read()   # any benign PE (e.g. setuptools' cli-64.exe)
inner = open(sys.argv[3], 'rb').read()  # another benign PE to embed as the "second stage"
xor = lambda d,k: bytes(c^k for c in d)
parts = [
  b'\0'*16, xor(b'http://evil-c2.xyz/gate.php\0', 0x5A),
  b'\0'*16, base64.b64encode(b'https://payload.top/stage2.bin'),
  b'\0'*16, base64.b64encode(base64.b64encode(b'cmd.exe /c vssadmin delete shadows /all /quiet')),
  b'\0'*16, b'3138352e3232302e3130312e3435',          # hex "185.220.101.45"
  b'\0'*16, b'x/ur.dab//:ptth',                        # reversed URL
  b'\0'*16, b'VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0IsDebuggerPresent\0',
  b'\0'*16, xor(inner[:4096], 0x37),                  # XOR'd second stage
  b'\0'*16, inner,                                     # plain embedded PE
]
open(sys.argv[1],'wb').write(base + b''.join(parts))
