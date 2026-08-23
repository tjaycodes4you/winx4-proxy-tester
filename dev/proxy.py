import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

UPSTREAM = ("127.0.0.1", 8769)


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_CONNECT(self):
        host, _, port = self.path.rpartition(":")
        upstream = socket.create_connection((host, int(port)), timeout=10)
        self.send_response(200, "Connection established")
        self.end_headers()

        def pipe(src, dst):
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass

        t1 = threading.Thread(target=pipe, args=(self.connection, upstream), daemon=True)
        t2 = threading.Thread(target=pipe, args=(upstream, self.connection), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        upstream.close()

    def do_GET(self):
        u = urlsplit(self.path)
        if u.hostname:
            upstream = (u.hostname, u.port or 80)
            path = u.path or "/"
        else:
            upstream = UPSTREAM
            path = self.path or "/"
        s = socket.create_connection(upstream, timeout=5)
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {self.headers['Host']}\r\n"
            f"X-Forwarded-For: {self.client_address[0]}\r\n"
            "Connection: close\r\n\r\n"
        ).encode()
        s.sendall(req)
        data = b""
        while True:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        s.close()
        head, _, body = data.partition(b"\r\n\r\n")
        code = int(head.split(b"\r\n", 1)[0].split()[1])
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass


class ProxyServer(ThreadingHTTPServer):
    request_queue_size = 500
    daemon_threads = True


if __name__ == "__main__":
    server = ProxyServer(("127.0.0.1", 8770), ProxyHandler)
    server.serve_forever()
