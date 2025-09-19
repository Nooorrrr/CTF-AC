python3 - << 'PY'
import re
b = open("space_invaders.nes","rb").read()
chunks = re.findall(rb'([0-9a-fA-F]{2}(?:\$\$\$[0-9a-fA-F]{2}){3,})', b)
flag = ''.join(''.join(chr(int(x,16)) for x in c.split(b'$$$')) for c in chunks)
print(flag)
PY

# ctf{9f1b438164dbc8a6249ba5c66fc0d6195b5388beed890680bf616021f2582248}