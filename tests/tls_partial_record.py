"""Run with: python3 tls_partial_record.py /path/to/eli_tls_io_test.

Requires Python's ssl module and openssl; all keys and certificates are temporary.
"""
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import time


with tempfile.TemporaryDirectory() as directory:
    cert = pathlib.Path(directory) / "cert.pem"
    key = pathlib.Path(directory) / "key.pem"
    subprocess.run([
        "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost",
    ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.num_tickets = 0
    context.load_cert_chain(cert, key)
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(5)
        client = subprocess.Popen([sys.argv[1], str(listener.getsockname()[1])])
        try:
            with listener.accept()[0] as peer:
                peer.settimeout(5)
                incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
                tls = context.wrap_bio(incoming, outgoing, server_side=True)
                while True:
                    try:
                        tls.do_handshake()
                        peer.sendall(outgoing.read())
                        break
                    except ssl.SSLWantReadError:
                        peer.sendall(outgoing.read())
                        data = peer.recv(16384)
                        assert data, "client closed during handshake"
                        incoming.write(data)
                tls.write(b"hello")
                record = outgoing.read()
                assert record[0] == 23 and len(record) > 6
                # Complete record header plus only one encrypted byte: the old
                # blocking BIO waits here beyond the client's 100ms deadline.
                peer.sendall(record[:6])
                time.sleep(0.3)
                peer.sendall(record[6:])
                assert client.wait(timeout=5) == 0
        finally:
            if client.poll() is None:
                client.kill()
            client.wait()
print("partial TLS record deadline and resumed/buffered reads passed")
