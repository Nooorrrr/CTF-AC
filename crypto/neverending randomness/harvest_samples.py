# harvest_samples.py
import socket, time
HOST = "ctf.ac.upt.ro"
PORT = 9195
OUT = "samples.txt"
N = 300
with open(OUT,"w") as f:
    for i in range(N):
        try:
            s = socket.create_connection((HOST, PORT), timeout=6)
            data = s.recv(8192)
            s.close()
            line = data.decode().strip()
            print(i, line)
            f.write(line + "\n")
            time.sleep(0.15)
        except Exception as e:
            print("err", e)
            time.sleep(1)
