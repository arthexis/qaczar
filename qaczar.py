#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that experiments with rapid application development.
# by machinemade@hotmail.com 2022

#   GUIDELINES
# - Keep the line width to less than 100 characters.
# - Use functions, not classes, for modularity, composability and encapsulation.
# - Functions should not reference functions or globals from later in the script.
# - Prioritize stability and clarity over features.
# - Avoid using asynchrony, concurrency, multiprocessing, multithreading, etc. Use RPC instead.
# - Use the standard library, not third-party libraries. Seriously.
# - Sometimes its ok to break the rules, take advantage of the language.


#@# 1. LOCAL SYSTEM

import os
import sys
import time
import typing as t


PID = os.getpid()

def iso8601() -> str: 
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str, _at=None) -> None: 
    global PID
    f = _at or sys._getframe(1)  
    print(f'[{PID}:{f.f_lineno} {iso8601()}] {f.f_code.co_name}: {msg}', file=sys.stderr)

def halt(msg: str) -> t.NoReturn:
    f = sys._getframe(1)
    # TODO: Consider additional cleanup or information gathering.
    emit(f"{msg} <- Final message.", _at=f); 
    emit(f"Halting all processes.", _at=f)
    sys.exit(0)

def read_file(fn: str, encoding=None) -> bytes:
    with open(fn, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def write_file(fn: str, data: bytes | str, encoding=None) -> None:
    if encoding and not isinstance(data, str): data = str(data)
    with open(fn, 'wb' if not encoding else 'w', encoding=encoding) as f: f.write(data)

def mtime_file(fn: str) -> float:
    if not os.path.isfile(fn): return 0
    return os.path.getmtime(fn)


#@# 2. SUBPROCESSING

import atexit
import subprocess as sp

def arg_line(*args: tuple[str], **kwargs: dict) -> tuple[str]:
    for k, v in kwargs.items(): args += (f'--{k}={str(v)}', )
    return args

def start_python(*args: list[str], **kwargs: dict) -> sp.Popen:
    args = arg_line(*args, **kwargs)
    if args[0] == __file__: 
        # Update the parent pid to the current pid.
        args += (f'--pid={os.getpid()}', )
    s = sp.Popen([sys.executable, *[str(a) for a in args]])
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"Started script {s.args=} {s.pid=}.")
    return s

def restart_python(proc: sp.Popen = None) -> sp.Popen:
    proc.terminate(); proc.wait()
    atexit.unregister(proc.terminate)
    args = proc.args + (os.getpid(),) if proc.args[0] == __file__ else args
    return start_python(*args)

def terminate_python(proc: sp.Popen) -> None:
    proc.terminate(); proc.wait()
    atexit.unregister(proc.terminate)
    emit(f"Terminated {proc.args=} {proc.pid=}.")

def watch_over(proc: sp.Popen, fn: str) -> t.NoReturn:  
    # TODO: Figure out to send the parent pid to the child.
    source, old_mtime, stable = read_file(fn), mtime_file(fn), True
    while True:
        time.sleep(2.6)
        if (new_mtime := mtime_file(fn)) != old_mtime:
            mutation, old_mtime = read_file(fn), new_mtime
            if mutation != source:
                emit(f"Mutation detected. Restart {fn=}.")
                proc, stable = restart_python(proc), False
            continue
        if proc.poll() is not None:
            if proc.returncode == 0:
                sys.exit(0)
            if stable:
                emit(f"Script died {proc.args=} {proc.pid=}. Restarting.")
                proc, stable = restart_python(proc), False
                continue
            if (mutation := read_file(fn)) != source:
                emit(f"Rolling back {fn=}.")
                write_file(fn, source)
                proc = restart_python(proc)
                continue
            halt(f"Unstable {fn=}. Check source.")
        if not stable:
            emit(f"Stabilizing {proc.pid=}.")
            source, stable = read_file(fn), True
            continue
            
def watch_self(role: str, pid: str = None, **kwargs: dict) -> t.NoReturn:
    if pid is not None: 
        emit(f"Kill obsolete watcher {pid=}.")
        os.kill(int(pid), 9)
    emit(f"Watch over {__file__} as {role=}.")
    kwargs['role'] = role
    # TODO: Catch errors and restart or apply other remediation.
    watch_over(start_python(__file__, **kwargs), __file__)


#@# 3. META-PROGRAMMING

import functools

def dedent(code: str) -> str:
    # TODO: Make it work with tabs.
    indent = len(code) - len(code.lstrip()) - 1
    return '\n'.join(line[indent:] for line in code.splitlines())

def timed(f: t.Callable) -> t.Callable:
    # TODO: Extract timed results from the log.
    # TODO: Think about something to keep track of decorators.
    @functools.wraps(f)
    def timed(*args, **kwargs):
        start = time.time(); elapsed = time.time() - start
        result = f(*args, **kwargs)
        emit(f"Function <{f.__name__}> {args=} {kwargs=} took {elapsed:.4f} seconds.")
        return result
    return timed

def extract_todos(fname: str) -> list[str]:
    # TODO: Generalize to extract any comments.
    # TODO: Extract constributions (how much a function is doing).
    todos = []
    for line in read_file(fname, encoding='utf-8').splitlines():
        if (todo := line.lstrip().split('#', 1)[0].strip()) and todo.startswith('TODO:'):
            todos.append(todo[5:].strip())
    return todos


#@# 4. CONTENT MANAGEMENT

import io
import doctest
import xml.dom.minidom as dom
from contextlib import redirect_stdout

WORKDIR = os.path.join(os.path.dirname(__file__), '.work')

def work_path(fname: str) -> str:
    global WORKDIR
    return os.path.join(WORKDIR, fname)

def write_work_file(fname: str, data: bytes | str, encoding='utf-8') -> None:
    # TODO: Test -> Make it choose the work directory automatically.
    global WORKDIR
    if not os.path.isdir(WORKDIR): os.mkdir(WORKDIR)
    write_file(work_path(fname), data, encoding)

@timed
def process_html(fname: str, context: dict) -> str:
    # TODO: Fix error handling.
    document = dom.parseString(read_file(fname, encoding='utf-8'))
    context['document'] = document
    for node in document.getElementsByTagName('script'):
        if node.getAttribute('type') == 'text/python':
            source = dedent(node.firstChild.data)
            with redirect_stdout(io.StringIO()) as stdout:
                exec(source, None, context)
                node.parentNode.replaceChild(dom.parseString(stdout.getvalue()).firstChild, node)            
    xml = document.toxml()
    write_work_file(fname, xml[xml.index('?>') + 2:], encoding='utf-8')
    return f'/.work/{fname}'

@timed
def process_python(fname: str, context: dict) -> str:
    emit(f"Test {fname=} {context=}.")
    with redirect_stdout(io.StringIO()) as stdout:
        result = doctest.testfile(fname, optionflags=doctest.ELLIPSIS)
        # TODO: Add more tests and error handling.
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
    
def process_file(fname: str, context: dict) -> str:
    # TODO: Single dispatch? Add more file types.
    if fname.endswith('.html'): return process_html(fname, context)
    if fname.endswith('.py'): return process_python(fname, context)
    return f'/{fname}'


#@# 5. COMMUNICATION

import ssl
import secrets
import importlib
import datetime as dt
import http.server as hs
import socketserver as ss
import urllib.parse as parse

def receive_post(data: dict) -> str:
    # TODO: Figure out a more robust way to handle post data.
    # TODO: Consider using a database (sqlite3?)
    emit(f"Received {data=}.")
    fname = secrets.token_hex(8) + '.txt'
    write_work_file(fname, data)
    return f'/.work/{fname}'

def pip_import(module: str) -> t.Any:
    # TODO: Add option to import from a local directory, or specify a version.
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
def generate_certs(ser, rsa, x509, hashes, /, keyname: str, certname: str) -> None:
    # TODO: Use a CA if available.
    # TODO: Figure out if we are the CA.
    site = 'qaczar.com'
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    write_file(keyname, key.private_bytes(
            encoding=ser.Encoding.PEM,
            format=ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption()))
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, site)])
    cert = x509.CertificateBuilder() \
            .subject_name(name) \
            .issuer_name(name) \
            .public_key(key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(dt.datetime.utcnow()) \
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3)) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(site)]), critical=False) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(key, hashes.SHA256())
    write_file(certname, cert.public_bytes(ser.Encoding.PEM))

@timed
def setup_files():
    if not os.path.exists('.work'): os.mkdir('.work')
    if not os.path.exists('.ssl'): os.mkdir('.ssl')
    if not os.path.exists('.ssl/cert.pem') or not os.path.exists('.ssl/key.pem'):
        emit("Generating SSL certificates for localhost.")
        generate_certs(keyname='.ssl/key.pem', certname='.ssl/cert.pem',)

def build_server() -> tuple:
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain('.ssl/cert.pem', '.ssl/key.pem')
    
    class SSLServer(ss.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
            ss.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
            self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True) 

    class Handler(hs.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            emit(f"{self.address_string()} {format % args}")

        @property
        def content_length(self) -> int:
            return int(self.headers.get('content-length', 0))
        
        def rfile_read(self, encoding: str = 'utf-8') -> bytes:
            return self.rfile.read(self.content_length).decode(encoding)

        def build_context(self, path:str, method: str = None) -> dict:
            if '?' not in path: qs = ''
            else: path, qs = path.split('?', 1)
            context = {'ip': self.client_address[0], 'ts': iso8601()}
            context['qs'] = parse.parse_qs(qs)
            if method == 'POST':
                context['post'] = parse.parse_qs(self.rfile_read())
            else: context['post'] = {}
            return context

        def build_response(self, method: str = None) -> bool:
            path = '/qaczar.html' if self.path == '/' else self.path
            context = self.build_context(path, method)
            self.path = process_file(path[1:], context)

        def do_HEAD(self) -> None:
            self.build_response('HEAD'); return super().do_HEAD()
            
        def do_GET(self) -> None:
            self.build_response('GET'); return super().do_GET()
        
        def do_POST(self) -> None:
            self.build_response('POST'); return super().do_GET()

    return SSLServer, Handler

def server_loop(address:str=None, **kwargs) -> t.NoReturn:
    # TODO: Launch a delegate to perform smoke tests and github actions.
    if address is not None and ':' in address:
        host, port = address.split(':')
        server_cls, handler_cls = build_server()
        with server_cls((host, int(port)), handler_cls) as httpd:
            emit(f"Serving at https://{host}:{port}")
            atexit.register(httpd.shutdown)
            httpd.serve_forever()

def split_args(args: list[str]) -> tuple[tuple, dict]:
    # TODO: Could fail if args are out of order? See if it matters.
    largs, kwargs = [], {}
    for arg in args:
        if '=' in arg: 
            __key, __value = arg[2:].split('=')
            kwargs[__key] = __value
        else: largs.append(arg)
    emit(f"Split args {kwargs=}")
    return tuple(largs), kwargs



#@# 6. MAIN DISPATCHER

if __name__ == "__main__":
    if len(sys.argv) == 1:
        # In this case we know we always want to start as a watcher.
        setup_files()
        watch_self(role='watcher')
    else:
        __args, __kwargs = split_args(sys.argv[1:])
        __role = __kwargs.pop('role')
        WORKDIR = os.path.join(os.path.dirname(__file__), f'.{__role}')
        emit(f"In watched subprocess {__role=} {__args=} {__kwargs=} ({WORKDIR=})")
        # Determine what to do next based on the role.
        if __role == 'server':
            __kwargs['address'] = __kwargs.get('address', 'localhost:9443')
            server_loop(**__kwargs)
        if __role == 'watcher':
            __target = __kwargs.pop('target', 'server')
            watch_self(__target, *__args, **__kwargs)
        halt(f"Not implemented {__role=}")


__all__ = ['emit', 'iso8601', 'EPOCH']


#@# 7. TESTING

