import socket, time

HOST, PORT = "tcp.flagyard.com", 15838

class Hokan:
    def __init__(self, host=HOST, port=PORT, boot_timeout=120):
        self.s = socket.create_connection((host, port), timeout=boot_timeout)
        self.s.settimeout(boot_timeout)
        self.buf = b""
        self._until(b"> ")          # wait for sage to boot
        self.s.settimeout(60)
        self.n = 0
    def _until(self, tok):
        while tok not in self.buf:
            d = self.s.recv(65536)
            if not d:
                raise EOFError(f"closed, buf={self.buf!r}")
            self.buf += d
        i = self.buf.find(tok)
        out, self.buf = self.buf[:i], self.buf[i+len(tok):]
        return out
    def query(self, v):
        assert len(v) == 11 and self.n < 8
        self.s.sendall((",".join(str(int(x)) for x in v)).encode() + b"\n")
        self.n += 1
        line = self._until(b"\n")
        val = int(line.strip())
        if self.n < 8:
            self._until(b"> ")
        else:
            self._until(b"> ")
        return val
    def answer(self, s):
        self.s.sendall(s.encode() + b"\n")
        self.s.settimeout(20)
        out = b""
        try:
            while True:
                d = self.s.recv(65536)
                if not d: break
                out += d
        except Exception:
            pass
        return out.decode(errors="replace")
    def close(self):
        try: self.s.close()
        except Exception: pass

if __name__ == "__main__":
    import sys, json
    # identical query set on a fresh connection -> are the answers the same?
    QS = [[1]*11, [2]*11, [3]*11, [2,3,5,7,11,13,17,19,23,29,31], [0]*11, [1,0,0,0,0,0,0,0,0,0,0], [5]*11, [7]*11]
    t0 = time.time()
    h = Hokan()
    print(f"# booted in {time.time()-t0:.1f}s", flush=True)
    res = [h.query(q) for q in QS]
    for q, r in zip(QS, res):
        print(f"{q} -> {r}")
    print(json.dumps(res))
    h.close()
