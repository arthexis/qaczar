#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script designed to experiment with rapid application development.
# H. V. D. C. by Rafa Guillén (arthexis@gmail.com) 2022-2023

# - Keep the line width to less than 100 characters.
# - Use functions, not classes, for modularity, composability and encapsulation.
# - Functions should not reference functions or globals from later in the script.
# - Prioritize stability and clarity over features.
# - Sometimes its ok to break the rules, take advantage of the language.


import os
import io
import sys
import time
import atexit
import doctest
import secrets
import importlib
import contextlib
import typing as t
import datetime as dt
import subprocess as sp
import xml.dom.minidom as md


RUNLEVEL = 0
HOST, PORT = 'localhost', 8080
HOME = '/qaczar.html'


def now() -> str:  # Time in UTC ISO format.
    """Ensure time is not running backwards.

    >>> import qaczar, time
    >>> qaczar.now() >= qaczar.EPOCH
    True

    """
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

EPOCH = now()  # Time when this instance was started or loaded.

def emit(msg: str) -> None: 
    f = sys._getframe(1)  # Caller's frame (could break in future Python versions)
    print(f'[{RUNLEVEL}:{f.f_lineno}] [{now()}] {f.f_code.co_name}: {msg}', file=sys.stderr)

def halt(msg: str, code: int=1) -> t.NoReturn:
    emit(msg + " Halting."); sys.exit(code)

def read_file(fname: str, encoding=None) -> bytes:
    with open(fname, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def write_file(fname: str, data: bytes | str, encoding=None) -> None:
    if encoding and not isinstance(data, str): data = str(data)
    with open(fname, 'wb' if not encoding else 'w', encoding=encoding) as f: f.write(data)

def mtime(fname: str) -> float:
    return os.path.getmtime(fname)

def run(*args: list[str]) -> sp.Popen:
    s = sp.Popen([sys.executable, *[str(a) for a in args]])
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"{s.args=} {s.pid=}.")
    return s

def restart(s: sp.Popen = None) -> sp.Popen:
    s.terminate(); s.wait()
    atexit.unregister(s.terminate)
    args = s.args + (os.getpid(),) if s.args[0] == __file__ else args
    return run(*args)

# Watch over s to ensure it never dies. If it does, create a new one.
def watch_over(s: sp.Popen, fname: str) -> t.NoReturn:  
    delay, stable = 2, True
    source, old_mtime = read_file(fname), mtime(fname)
    while True:
        time.sleep(delay)
        if (new_mtime := mtime(fname)) != old_mtime:
            mutation, old_mtime = read_file(fname), new_mtime
            if mutation != source:
                emit(f"Mutation detected. Restart {fname=}.")
                s, stable, delay = restart(s), False, delay * 2
            continue
        if s.poll() is not None:
            if s.returncode == 0:
                halt(f"Process {s.pid} exited normally.")
            if stable:
                emit(f"Script died {s.args=} {s.pid=}. Restarting.")
                s, stable, delay = restart(s), False, delay * 2
                continue
            if (mutation := read_file(fname)) != source:
                emit(f"Rolling back {fname=}.")
                write_file(fname, source)
                s = restart(s)
                continue
            halt(f"Unstable {fname=}. Check source.")
        if not stable:
            emit(f"Stabilizing {s.pid=}.")
            source, stable = read_file(fname), True
            continue
        delay = delay // 2 if delay > 2 else 2
            
def watch_under(watcher=None) -> t.NoReturn:
    if watcher: os.kill(int(watcher), 9)
    watch_over(run(__file__, __file__), __file__)

def dedent(code: str) -> str:
    indent = len(code) - len(code.lstrip()) - 1
    return '\n'.join(line[indent:] for line in code.splitlines())

def timed(f) -> t.Callable:
    def timed(*args, **kwargs):
        start = time.time()
        result = f(*args, **kwargs)
        emit(f"{f.__name__} {args=} {kwargs=} took {time.time() - start:.4f} seconds.")
        return result
    return timed

def write_work_file(fname: str, data: bytes | str, encoding='utf-8') -> None:
    write_file(os.path.join('.work', fname), data, encoding=encoding)

@timed
def process_html(fname: str, context: dict) -> str:
    document = md.parseString(read_file(fname, encoding='utf-8'))
    context['document'] = document
    for node in document.getElementsByTagName('script'):
        if node.getAttribute('type') == 'text/python':
            exec(dedent(node.firstChild.data), None, context)
            node.parentNode.removeChild(node)
    write_work_file(fname, document.toxml())
    return f'/.work/{fname}'

@timed
def process_python(fname: str, context: dict) -> str:
    emit(f"Test {fname=} {context=}.")
    with contextlib.redirect_stdout(io.StringIO()) as stdout:
        result = doctest.testfile(fname, optionflags=doctest.ELLIPSIS)
        if result.failed:
            fname = fname[:-2] + 'html'
            write_work_file(fname, stdout.getvalue())
            return f'/.work/{fname}'
        if context.get('post'):
            module = importlib.import_module(fname[:-3])
            if hasattr(module, 'receive_post'):
                return module.receive_post(context['post'])
        emit(f"Serving {fname=} as-is.")
        return f'/{fname}'

def receive_post(data: dict) -> str:
    emit(f"Received {data=}.")
    fname = secrets.token_hex(8) + '.txt'
    # Convert data to string before writing.
    write_work_file(fname, data)
    return f'/.work/{fname}'

def pip_import(module: str) -> t.Any:
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError:
        emit(f"Installing {module=}.")
        if '.' in module: module = module.split('.')[0]
        sp.run([sys.executable, '-m', 'pip', 'install', module])
        return importlib.import_module(module)
    
def imports(*modules: tuple[str]) -> t.Callable:
    def decorator(f):
        def wrapper(*args, **kwargs):
            return f(*(pip_import(module) for module in modules), *args, **kwargs)
        return wrapper
    return decorator
    
@imports('cryptography.hazmat.primitives.serialization',
    'cryptography.hazmat.primitives.asymmetric.rsa',
    'cryptography.x509',
    'cryptography.hazmat.primitives.hashes')
def generate_certs(serialization, rsa, x509, hashes, /, keyname: str, certname: str) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    write_file(keyname, key.private_bytes(encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, 'qaczar.com')])
    cert = x509.CertificateBuilder() \
            .subject_name(name) \
            .issuer_name(name) \
            .public_key(key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(dt.datetime.utcnow()) \
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3)) \
            .add_extension( 
                x509.SubjectAlternativeName([x509.DNSName('qaczar.com')]), critical=False) \
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(key, hashes.SHA256())
    write_file(certname, cert.public_bytes(serialization.Encoding.PEM))

def setup_files():
    if not os.path.exists('.work'): os.mkdir('.work')
    if not os.path.exists('.ssl'): os.mkdir('.ssl')
    if not os.path.exists('.ssl/cert.pem') or not os.path.exists('.ssl/key.pem'):
        emit("Generating SSL certificates.")
        generate_certs(keyname='.ssl/key.pem', certname='.ssl/cert.pem',)

@imports('ssl', 'http.server', 'socketserver', 'urllib.parse')
def build_server(ssl, hs, ss, up) -> tuple:
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain('.ssl/cert.pem', '.ssl/key.pem')
    
    class SSLServer(ss.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
            ss.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
            self.socket = ssl_context.wrap_socket(self.socket, server_side=True)

    class Handler(hs.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            emit(f"{self.address_string()} {format % args}")

        def build_context(self, path:str, method: str = None) -> dict:
            if '?' in path: path, qs = path.split('?', 1)
            else: qs = ''
            context = {'get': up.parse_qs(qs), 'ip': self.client_address[0], 'ts': now()}
            if method == 'POST':
                length = int(self.headers.get('content-length', 0))
                context['post'] = up.parse_qs(self.rfile.read(length).decode('utf-8'))
            else: context['post'] = {}
            return context

        def build_response(self, method: str = None) -> bool:
            path = HOME if self.path == '/' else self.path
            context = self.build_context(path, method)
            if path.endswith('.html'):
                self.path = process_html(path[1:], context)
            elif path.endswith('.py'):
                self.path = process_python(path[1:], context)

        def do_HEAD(self) -> None:
            self.build_response('HEAD'); return super().do_HEAD()
            
        def do_GET(self) -> None:
            self.build_response('GET'); return super().do_GET()
        
        def do_POST(self) -> None:
            self.build_response('POST'); return super().do_GET()

    return SSLServer, Handler

def serve_forever(host: str, port: int) -> t.NoReturn:
    global HOME
    server_cls, handler_cls = build_server()
    with server_cls((host, port), handler_cls) as httpd:
        emit(f"Serving at https://{host}:{port}")
        httpd.serve_forever()

def main_loop(pid:str=None, address:str=None, *args: list[str]) -> t.NoReturn:
    emit(f"Starting {pid=} {args=}.")
    if pid is not None:
        emit(f"Kill watcher {pid=}. As above so below.")
        watch_under(watcher=pid)
    if address is not None and ':' in address:
        host, port = address.split(':')
        serve_forever(host, int(port))

# Begin script execution in self-watch mode by default.
if __name__ == "__main__":
    RUNLEVEL = 1
    setup_files()
    if len(sys.argv) == 1:
        watch_under()
    elif sys.argv[1] == __file__:
        RUNLEVEL = 2
        main_loop(*sys.argv[2:], address=f'{HOST}:{PORT}')
    watch_over(run(*sys.argv[1:]), sys.argv[1])

__all__ = ['emit', 'now', 'EPOCH']

