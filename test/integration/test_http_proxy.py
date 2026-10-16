import argparse
import base64
import http.server
import http.client
import json
import re
import shutil
import socket
import socketserver
import ssl
import traceback
import subprocess
import tempfile
import threading
import time
from pathlib import Path


def wait_for(check, timeout=90):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.2)
    raise AssertionError("Timed out waiting for local test service")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Services:
    def __init__(self, root):
        self.root = root
        self.processes = []

    def start(self, name, args, env=None):
        log = (self.root / (name + ".log")).open("w+")
        process = subprocess.Popen([str(a) for a in args], cwd=self.root, stdout=log, stderr=log, env=env)
        self.processes.append((process, log))
        return process

    def close(self):
        for process, _ in reversed(self.processes):
            if process.poll() is None:
                process.terminate()
        for process, log in reversed(self.processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            log.close()


def run(proxy, helper, dht_server, root, scenario=None, client_proxy=None, server_proxy=None,
        compatibility=False, expected_transport="QUIC", quic_probe=None, dht_resolver=None):
    client_proxy = client_proxy or proxy
    server_proxy = server_proxy or proxy

    def key(name):
        path = root / name
        out = subprocess.check_output([helper, "-m", "keys", "-n", path], cwd=root, text=True)
        hex_id, b64_id = out.split()
        return path, hex_id, b64_id

    services = Services(root)
    try:
        dht_port = free_port()
        dht_dir = root / "dht"
        (dht_dir / "keyring").mkdir(parents=True)
        dht_key, hex_id, b64_id = key("dht-key")
        shutil.copyfile(dht_key, dht_dir / "keyring" / hex_id)
        addr_list = {"@type": "adnl.addressList", "addrs": [
            {"@type": "adnl.address.udp", "ip": 2130706433, "port": dht_port}],
            "version": int(time.time()), "reinit_date": int(time.time()), "priority": 0, "expire_at": 0}
        signed = json.loads(subprocess.check_output([
            helper, "-m", "dht", "-k", dht_key, "-a", json.dumps(addr_list)], cwd=root))
        global_config = root / "global.json"
        global_config.write_text(json.dumps({"@type": "config.global", "dht": {
            "@type": "dht.config.global", "static_nodes": {"@type": "dht.nodes", "nodes": [signed]},
            "k": 3, "a": 3},
            "liteservers": [{"ip": 2130706433, "port": free_port(),
                "id": {"@type": "pub.ed25519", "key": b64_id}}],
            "validator": {"@type": "validator.config.global", "zero_state": {
                "workchain": -1, "shard": -9223372036854775808, "seqno": 0,
                "root_hash": "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
                "file_hash": "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="}}}))
        local_config = root / "dht.json"
        local_config.write_text(json.dumps({"@type": "engine.validator.config", "out_port": 0,
            "addrs": [{"@type": "engine.addr", "ip": 2130706433, "port": dht_port,
                       "categories": [0], "priority_categories": []}],
            "adnl": [{"@type": "engine.adnl", "id": b64_id, "category": 0}],
            "dht": [{"@type": "engine.dht", "id": b64_id}],
            "gc": {"@type": "engine.gc", "ids": []}}))
        services.start("dht", [dht_server, "-C", global_config,
                               "-c", local_config, "-D", dht_dir, "-v", "3"])

        payload = bytes(range(256)) * 12288
        stream_consumed = threading.Event()

        upload_started = threading.Event()
        upload_cancelled = threading.Event()
        peer_half_closed = threading.Event()
        peer_received = bytearray()
        failures = []
        identity_requests = []

        def case(name, check):
            if scenario and scenario not in name:
                return
            try:
                check()
                print("PASS:", name, flush=True)
            except Exception:
                failures.append(name)
                traceback.print_exc()
                for _, log in services.processes:
                    log.flush()
                    lines = Path(log.name).read_text(errors="replace").splitlines()
                    print("--- failure:", log.name, "---", flush=True)
                    print("\n".join(lines[-65:]), flush=True)

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_HEAD(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()

            def do_GET(self):
                if self.path.endswith('/identity-check/small'):
                    identity_requests.append(self.path)
                if self.path.endswith('/no-content') or self.path.endswith('/not-modified'):
                    self.send_response(204 if self.path.endswith('/no-content') else 304)
                    if self.path.endswith('/not-modified'):
                        self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    return
                self.send_response(200)
                if self.path.endswith('/chunked'):
                    self.send_header("Transfer-Encoding", "chunked")
                    self.send_header("Trailer", "X-Proxy-Test")
                    self.end_headers()
                    for offset in range(0, len(payload), 32768):
                        chunk = payload[offset:offset + 32768]
                        self.wfile.write(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                    self.wfile.write(b"0\r\nX-Proxy-Test: complete\r\n\r\n")
                    return
                if self.path.endswith('/eof'):
                    self.send_header("Connection", "close")
                    self.end_headers()
                    self.wfile.write(payload)
                    self.close_connection = True
                    return
                body = b"hello-proxy" if self.path.endswith('/small') else payload
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if self.path.endswith('/truncated'):
                    self.wfile.write(body[:65536])
                    self.wfile.flush()
                    self.close_connection = True
                elif self.path.endswith('/stream'):
                    self.wfile.write(body[:65536])
                    self.wfile.flush()
                    assert stream_consumed.wait(5), "Proxy buffered a slow response until completion"
                    self.wfile.write(body[65536:])
                else:
                    self.wfile.write(body)

            def do_POST(self):
                trailers = {}
                if self.path.endswith('/abort-upload'):
                    upload_started.set()
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                    if len(body) < int(self.headers["Content-Length"]):
                        upload_cancelled.set()
                    return
                if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
                    parts = []
                    while True:
                        size = int(self.rfile.readline().split(b";", 1)[0], 16)
                        if not size:
                            break
                        parts.append(self.rfile.read(size))
                        assert self.rfile.read(2) == b"\r\n"
                    while line := self.rfile.readline().strip():
                        name, value = line.decode().split(":", 1)
                        trailers[name.lower()] = value.strip()
                    body = b"".join(parts)
                else:
                    body = self.rfile.read(int(self.headers["Content-Length"]))
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                if trailers:
                    self.send_header("X-Upload-Trailer", trailers.get("x-upload-test", "missing"))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                while data := self.request.recv(65536):
                    self.request.sendall(data)

        class AfterEof(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                chunks = []
                while data := self.request.recv(65536):
                    chunks.append(data)
                self.request.sendall(b"after-eof:" + b"".join(chunks))

        class WriteEofFirst(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                self.request.sendall(b"server-finished")
                self.request.shutdown(socket.SHUT_WR)
                while data := self.request.recv(65536):
                    peer_received.extend(data)
                peer_half_closed.set()

        certificate, tls_key = root / "test-cert.pem", root / "test-key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", tls_key, "-out", certificate, "-subj", "/CN=localhost", "-days", "1"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(certificate, tls_key)
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler) as origin, \
                socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as echo, \
                socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo) as tls_echo, \
                socketserver.ThreadingTCPServer(("127.0.0.1", 0), AfterEof) as after_eof, \
                socketserver.ThreadingTCPServer(("127.0.0.1", 0), WriteEofFirst) as write_eof_first:
            tls_echo.socket = tls_context.wrap_socket(tls_echo.socket, server_side=True)
            for server in (origin, echo, tls_echo, after_eof, write_eof_first):
                server.daemon_threads = True
                threading.Thread(target=server.serve_forever, daemon=True).start()
            server_dir = root / "proxy-server"
            (server_dir / "keyring").mkdir(parents=True)
            server_key, server_hex, _ = key("proxy-key")
            shutil.copyfile(server_key, server_dir / "keyring" / server_hex)
            address = subprocess.check_output([helper, "-m", "adnlid", "-k", server_key],
                                              cwd=root, text=True).split()[1]
            port = free_port()
            while port >= 64536:
                port = free_port()
            server_args = [server_proxy, "-a", f"127.0.0.1:{port}",
                "-A", address, "-C", global_config, "-D", server_dir, "-v", "3",
                "-R", f"*:80@127.0.0.1:{origin.server_port}",
                "-R", f"*:443@127.0.0.1:{echo.server_address[1]}",
                "-R", f"*:8443@127.0.0.1:{tls_echo.server_address[1]}",
                "-R", f"*:8444@127.0.0.1:{after_eof.server_address[1]}",
                "-R", f"*:8445@127.0.0.1:{write_eof_first.server_address[1]}"]
            reverse = services.start("proxy-server", server_args)
            resolver = dht_resolver or str(Path(helper).parent.parent / "dht" / "dht-resolve")
            with (root / "dht-ready.log").open("w") as ready_log:
                subprocess.run([resolver, "-C", str(global_config), "-p", str(free_port()),
                                "-k", server_hex, "-n", "address", "-i", "0", "-t", "30",
                                "-j", str(root / "reverse-address.json")],
                               stdout=ready_log, stderr=ready_log, timeout=35, check=True)
            entry_port = free_port()
            services.start("proxy-client", [client_proxy, "-p", entry_port, "-c", free_port(),
                "-C", global_config, "-D", root / "proxy-client", "-v", "3"])

            def listening():
                try:
                    with socket.create_connection(("127.0.0.1", entry_port), timeout=0.2):
                        return True
                except OSError:
                    return False

            wait_for(listening)
            url = f"http://{address}.adnl/"
            curl = ["curl", "--silent", "--show-error", "--fail", "--max-time", "45",
                    "--noproxy", "", "--proxy", f"http://127.0.0.1:{entry_port}"]
            def bootstrap_probe():
                result = subprocess.run([*curl, "--max-time", "5", url],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return result.stdout if result.returncode == 0 else None

            download = wait_for(bootstrap_probe)
            assert download == payload, "Proxy GET content mismatch"
            source = root / "payload.bin"
            source.write_bytes(payload)
            upload = subprocess.check_output([*curl, "--data-binary", "@" + str(source), url])
            assert upload == payload, "Proxy POST content mismatch"
            if not compatibility:
                streaming = http.client.HTTPConnection("127.0.0.1", entry_port, timeout=3)
                try:
                    streaming.request("GET", url + "stream", headers={"Host": address + ".adnl"})
                    response = streaming.getresponse()
                    assert response.status == 200
                    first = response.read(1)
                    assert first, "Slow origin did not deliver its first response byte"
                    stream_consumed.set()
                    streaming.sock.settimeout(10)
                    assert first + response.read() == payload, "Slow streaming response content mismatch"
                finally:
                    stream_consumed.set()
                    streaming.close()
                truncated = subprocess.run([*curl, '--max-time', '3', url + 'truncated'],
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                assert truncated.returncode in (18, 22, 52), (
                    'Truncated origin must promptly fail the downstream HTTP body', truncated.returncode,
                    truncated.stderr)
                assert subprocess.check_output([*curl, url]) == payload, 'Failure poisoned the next transfer'
            with socket.create_connection(("127.0.0.1", entry_port), timeout=20) as tunnel:
                tunnel.sendall(f"CONNECT {address}.adnl:443 HTTP/1.1\r\nHost: {address}.adnl:443\r\n\r\n".encode())
                headers = bytearray()
                while not headers.endswith(b"\r\n\r\n"):
                    part = tunnel.recv(1)
                    assert part, "CONNECT closed before response"
                    headers.extend(part)
                assert b" 200 " in headers, headers
                message = b"proxy-tunnel" * 500
                tunnel.sendall(message)
                received = bytearray()
                while len(received) < len(message):
                    part = tunnel.recv(len(message) - len(received))
                    assert part, "CONNECT closed before echo"
                    received.extend(part)
                assert received == message
            logs = "\n".join(Path(log.name).read_text(errors="replace") for _, log in services.processes)
            assert (f"Selected HTTP transport: {expected_transport}" in logs or
                    f"got HTTP request using {expected_transport}" in logs), "Wrong negotiated transport"
            print(f"PASS: negotiated {expected_transport}: GET and POST (3 MiB each), CONNECT", flush=True)
            if compatibility:
                for server in (origin, echo, tls_echo, after_eof, write_eof_first):
                    server.shutdown()
                return

            def identity_filtering():
                def probe(identity):
                    result = subprocess.run([quic_probe, f"127.0.0.1:{port + 1000}", identity,
                                             address + ".adnl"], text=True,
                                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
                    assert result.returncode == 0, result.stderr[-4000:]
                    reply = json.loads(result.stdout)
                    reply["peer_id"] = reply["peer_id"].lower()
                    assert reply["peer_id"] and not reply["timed_out"] and not reply["invalid_response"], reply
                    return reply

                allowed = probe(server_hex)
                assert allowed["peer_id"] == server_hex.lower() and allowed["http_status"] == 200, allowed
                before = len(identity_requests)
                rejected = probe("-")
                if rejected["peer_id"] == server_hex.lower():
                    assert rejected["http_status"] == 200, rejected
                    registered = re.findall(r"registered identity ([A-Za-z0-9+/=]+)",
                                            (root / "proxy-server.log").read_text(errors="replace"))
                    internal_ids = [base64.b64decode(value).hex() for value in registered]
                    internal = next(value for value in internal_ids if value != server_hex.lower())
                    before = len(identity_requests)
                    rejected = probe(internal)
                assert rejected["peer_id"] != server_hex.lower(), rejected
                assert rejected["http_status"] is None and rejected["stream_closed"], rejected
                assert len(identity_requests) == before, "Unregistered HTTP identity reached the origin"
                assert probe(server_hex)["http_status"] == 200, "Refusal broke the registered site identity"

            if quic_probe:
                case("QUIC identity filtering rejects internal identities", identity_filtering)

            def connect_tunnel(target_port):
                connection = socket.create_connection(("127.0.0.1", entry_port), timeout=5)
                connection.sendall(f"CONNECT {address}.adnl:{target_port} HTTP/1.1\r\n"
                                   f"Host: {address}.adnl:{target_port}\r\n\r\n".encode())
                headers = bytearray()
                while not headers.endswith(b"\r\n\r\n"):
                    part = connection.recv(1)
                    assert part, "CONNECT closed before response"
                    headers.extend(part)
                assert b" 200 " in headers, headers
                return connection

            def request_wire(connection, method, path, extra="", body=b""):
                connection.sendall(f"{method} {url}{path} HTTP/1.1\r\nHost: {address}.adnl\r\n"
                                   f"Connection: keep-alive\r\n{extra}\r\n".encode() + body)

            def read_response(reader, method="GET"):
                line = reader.readline()
                assert line.startswith(b"HTTP/1."), line
                status = int(line.split()[1])
                headers, trailers = {}, {}
                while line := reader.readline().strip():
                    name, value = line.decode().split(":", 1)
                    headers[name.lower()] = value.strip()
                body = bytearray()
                if method == "HEAD" or status in (204, 304):
                    return status, headers, bytes(body), trailers
                if headers.get("transfer-encoding", "").lower() == "chunked":
                    while True:
                        size = int(reader.readline().split(b";", 1)[0], 16)
                        if not size:
                            break
                        body.extend(reader.read(size))
                        assert reader.read(2) == b"\r\n"
                    while line := reader.readline().strip():
                        name, value = line.decode().split(":", 1)
                        trailers[name.lower()] = value.strip()
                elif "content-length" in headers:
                    body.extend(reader.read(int(headers["content-length"])))
                    assert len(body) == int(headers["content-length"])
                else:
                    body.extend(reader.read())
                return status, headers, bytes(body), trailers

            def framing_and_keep_alive():
                with socket.create_connection(("127.0.0.1", entry_port), timeout=5) as connection:
                    with connection.makefile("rb") as reader:
                        for method, path, status, expected in [
                            ("GET", "small", 200, b"hello-proxy"),
                            ("HEAD", "", 200, b""),
                            ("GET", "no-content", 204, b""),
                            ("GET", "not-modified", 304, b""),
                            ("GET", "chunked", 200, payload),
                            ("GET", "eof", 200, payload),
                            ("GET", "small", 200, b"hello-proxy"),
                        ]:
                            print("CHECK:", method, path, flush=True)
                            request_wire(connection, method, path)
                            actual, headers, body, trailers = read_response(reader, method)
                            assert (actual, body) == (status, expected), (method, path, actual, len(body))
                            if path == "chunked":
                                assert trailers.get("x-proxy-test") == "complete", trailers
                        parts = []
                        for offset in range(0, len(payload), 32768):
                            chunk = payload[offset:offset + 32768]
                            parts.append(f"{len(chunk):x}\r\n".encode() + chunk + b"\r\n")
                        parts.append(b"0\r\nX-Upload-Test: complete\r\n\r\n")
                        request_wire(connection, "POST", "chunked-upload",
                                     "Transfer-Encoding: chunked\r\nTrailer: X-Upload-Test\r\n", b"".join(parts))
                        status, headers, body, _ = read_response(reader)
                        assert status == 200 and body == payload
                        assert headers.get("x-upload-trailer") == "complete", headers
                        request_wire(connection, "GET", "small")
                        assert read_response(reader)[2] == b"hello-proxy"

            case("HEAD, 204, 304, chunked/trailers both ways, EOF and persistent HTTP connection", framing_and_keep_alive)

            def interrupted_upload():
                with socket.create_connection(("127.0.0.1", entry_port), timeout=5) as connection:
                    request_wire(connection, "POST", "abort-upload", f"Content-Length: {len(payload)}\r\n",
                                 payload[:131072])
                    assert upload_started.wait(3), "Upload never reached origin"
                assert upload_cancelled.wait(3), "Client abort did not close the incomplete origin upload"
                assert subprocess.check_output([*curl, url + "small"]) == b"hello-proxy"

            case("Interrupted upload propagates to origin and next request works", interrupted_upload)

            def half_close():
                with connect_tunnel(8444) as connection:
                    message = payload
                    connection.sendall(message)
                    connection.shutdown(socket.SHUT_WR)
                    received = bytearray()
                    while part := connection.recv(65536):
                        received.extend(part)
                    assert received == b"after-eof:" + message, (len(received), len(message))

            case("CONNECT write-half closure retains the response direction", half_close)

            def peer_half_close():
                with connect_tunnel(8445) as connection:
                    received = bytearray()
                    while part := connection.recv(65536):
                        received.extend(part)
                    assert received == b"server-finished", received
                    message = payload
                    connection.sendall(message)
                    connection.shutdown(socket.SHUT_WR)
                    assert peer_half_closed.wait(3), "Client EOF did not reach the half-closed backend"
                    assert peer_received == message, len(peer_received)

            case("CONNECT peer write-half closure retains upload direction", peer_half_close)

            def tls_and_idle_tunnel():
                client_context = ssl.create_default_context(cafile=str(certificate))
                with client_context.wrap_socket(connect_tunnel(8443), server_hostname="localhost") as connection:
                    for round_number in range(3):
                        message = bytes([round_number]) * (256 * 1024)
                        connection.sendall(message)
                        received = bytearray()
                        while len(received) < len(message):
                            part = connection.recv(len(message) - len(received))
                            assert part, "TLS tunnel closed during exchange"
                            received.extend(part)
                        assert received == message
                        if round_number == 0:
                            time.sleep(51)

            case("Real TLS through CONNECT, including 51 seconds idle", tls_and_idle_tunnel)

            def reconnect():
                reverse.terminate()
                reverse.wait(timeout=5)
                services.start("proxy-server-restarted", server_args)
                first = subprocess.run([*curl, "--max-time", "35", url + "small"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                assert first.returncode in (0, 22, 28, 52, 56), first.stderr
                if first.returncode == 0:
                    assert first.stdout == b"hello-proxy"
                assert subprocess.check_output([*curl, "--max-time", "10", url + "small"]) == b"hello-proxy"

            case("QUIC connection reestablished after isolated reverse restart", reconnect)
            assert not failures, "Failed scenarios: " + ", ".join(failures)
            for server in (origin, echo, tls_echo, after_eof, write_eof_first):
                server.shutdown()

    except Exception:
        for _, log in services.processes:
            log.flush()
            print(f"--- {log.name} ---")
            print(Path(log.name).read_text(errors="replace")[-6000:])
        raise
    finally:
        services.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--proxy", type=Path, required=True)
    parser.add_argument("--key-helper", type=Path, required=True)
    parser.add_argument("--dht-server", type=Path, required=True)
    parser.add_argument("--dht-resolver", type=Path, required=True)
    parser.add_argument("--quic-probe", type=Path)
    parser.add_argument("--scenario", help="Run only added scenarios whose name contains this text")
    parser.add_argument("--client-proxy", type=Path)
    parser.add_argument("--server-proxy", type=Path)
    parser.add_argument("--compatibility", action="store_true", help="Test legacy-compatible GET, POST and CONNECT")
    parser.add_argument("--expected-transport", choices=("QUIC", "RLDP2"), default="QUIC")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="ton-quic-apps-") as directory:
        run(args.proxy.resolve(), args.key_helper.resolve(), args.dht_server.resolve(), Path(directory), args.scenario,
            args.client_proxy.resolve() if args.client_proxy else None,
            args.server_proxy.resolve() if args.server_proxy else None,
            args.compatibility, args.expected_transport,
            args.quic_probe.resolve() if args.quic_probe else None, args.dht_resolver.resolve())
