# harvest_and_try.py
import socket, time, json

HOST = "ctf.ac.upt.ro"
PORT = 9195
OUT = "samples.txt"
N = 200

with open(OUT, "w") as f:
    for i in range(N):
        try:
            s = socket.create_connection((HOST, PORT), timeout=5)
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
                if b"\n" in data:
                    break
            s.close()
            line = data.decode().strip()
            print(i, line)
            f.write(line + "\n")
            time.sleep(0.2)  # be polite; adjust rate if needed
        except Exception as e:
            print("err", e)
            time.sleep(1)
