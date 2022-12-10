#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that experiments with rapid application development.
# by R.J. Guillén (rjguillen [at] qaczar.com) 2022

#   GUIDELINES
# - Keep the line width to less than 100 characters.
# - Use functions, not classes, for modularity, composability and encapsulation.
# - Functions should not reference functions or globals from later in the script.
# - TODO items should be encapsulated in functions to simplify refactoring.
# - Prioritize stability and clarity over new features.
# - Avoid using asynchrony, concurrency, multiprocessing, multithreading, etc. Use HTTPS for RPC.
# - Use the standard library, not third-party libraries. Seriously.
# - Sometimes its ok to break the rules, take advantage of the language.
# - In case of doubt, just run the script and see what happens.


#@# 1. LOCAL PLATFORM

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
    # TODO: See if we need to standardize on UTF-8.
    with open(fn, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def write_file(fn: str, data: bytes | str, encoding=None) -> None:
    if encoding and not isinstance(data, str): data = str(data)
    with open(fn, 'wb' if not encoding else 'w', encoding=encoding) as f: f.write(data)

def mtime_file(fn: str) -> float:
    if not os.path.isfile(fn): return 0.0
    return os.path.getmtime(fn)


#@# 2. META-PROGRAMMING

import importlib
import functools

def dedent(code: str) -> str:
    # TODO: Make it work with tabs.
    indent = len(code) - len(code.lstrip()) - 1
    return '\n'.join(line[indent:] for line in code.splitlines())

def timed(f: t.Callable) -> t.Callable:
    # TODO: Extract timed results from the log during testing?
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


#@# 2. SUBPROCESSING

import atexit
import subprocess as sp

def arg_line(*args: tuple[str], **kwargs: dict) -> tuple[str]:
    for k, v in kwargs.items(): args += (f'--{k}={str(v)}', )
    return args

def split_arg_line(args: list[str]) -> tuple[tuple, dict]:
    largs, kwargs = [], {}
    for arg in args:
        if '=' in arg: 
            __key, __value = arg[2:].split('='); kwargs[__key] = __value
        else: largs.append(arg)
    return tuple(largs), kwargs

def start_python(script: str, *args: list[str], **kwargs: dict) -> sp.Popen:
    if script == __file__: kwargs['opid'] = os.getpid()
    line_args = [str(a) for a in arg_line(*args, **kwargs)]
    proc = sp.Popen([sys.executable, script, *line_args], daemon=True)
    proc.stdout, proc.stderr = sys.stdout, sys.stderr, 
    proc._args, proc._kwargs = args, kwargs  # Magic for restart_python.
    atexit.register(proc.terminate)
    emit(f"Started python {script=} {proc.pid=}.")
    return proc

def terminate_python(proc: sp.Popen) -> tuple[tuple, dict]:
    proc.terminate(); proc.wait()
    # TODO: Check if the process is still alive.
    atexit.unregister(proc.terminate)
    emit(f"Terminated {proc.args=} {proc.pid=}.")
    return proc._args, proc._kwargs

def restart_python(proc: sp.Popen = None, opid=PID) -> sp.Popen:
    if proc: args, kwargs = terminate_python(proc)
    else: args, kwargs = [], {}
    kwargs['opid'] = opid
    return start_python(__file__, *args, **kwargs)

def linear_distance(source: str, mutation: str) -> int:
    distance = 0
    for line in source.splitlines():
        if line not in mutation: distance += 1
        else: mutation = mutation.replace(line, '', 1)
    return distance - len(mutation)

def watch_over(proc: sp.Popen, fn: str) -> t.NoReturn:  
    # TODO: Restart the watcher after it has restarted the server.
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
            if (mutation := read_file(fn)) != source :
                # TODO: Consider using a more sophisticated algorithm.
                if linear_distance(source, mutation) == 0:
                    emit(f"No mutation detected. Restart {fn=}. Mark unstable.")
                    proc, stable = restart_python(proc), False
                    continue
                else:
                    emit(f"Mutation detected. Restart {fn=}.")
                    proc, stable = restart_python(proc), True
                    continue
            halt(f"Unstable {fn=}. Check source.")
        if not stable:
            emit(f"Stabilizing {proc.pid=}.")
            source, stable = read_file(fn), True
            continue    
    

#@# 4. CONTENT GENERATION

import io
import xml.dom.minidom as dom
from contextlib import redirect_stdout

WORKDIR = os.path.join(os.path.dirname(__file__), '.work')

def set_workdir(role: str='work') -> None:
    global WORKDIR
    WORKDIR = os.path.join(os.path.dirname(__file__), f'.{role}')

def work_path(fname: str) -> str:
    global WORKDIR
    if not os.path.isdir(WORKDIR): os.mkdir(WORKDIR)
    return os.path.join(WORKDIR, fname)

def replace_node(*, old: dom.Node, new: str) -> None:
    old.parentNode.replaceChild(dom.parseString(new).firstChild, old)

def iter_scripts(document: dom.Document) -> t.Iterator[dom.Node]:
    for node in document.getElementsByTagName('script'):
        if node.getAttribute('type') == 'text/python': yield node

def exec_inline(source: str, *, context: dict) -> str:
    with redirect_stdout(io.StringIO()) as stdout:
        exec(source, None, context)
        return stdout.getvalue()

def process_html(fname: str, context: dict) -> str:
    # TODO: New function to automatically create a form from a function.
    document = dom.parseString(read_file(fname, encoding='utf-8'))
    context['document'] = document
    for node in iter_scripts(document):
        new_html = exec_inline(dedent(node.firstChild.data), context=context)
        replace_node(old=node, new=new_html)
    xml = document.toxml()
    write_file(wp := work_path(fname), xml[xml.index('?>') + 2:], encoding='utf-8')
    return wp
    
@timed
def dispatch_processor(fname: str, context: dict) -> str:
    if (processor := globals().get(f'process_{fname.split(".")[-1]}')):
        emit(f"Processing {fname=} with <{processor.__name__}>.")
        processor(fname, context)
    return f'/{fname}'


#@# 5. COMMUNICATION 

import ssl
import secrets
import importlib
import datetime as dt
import http.server as hs
import socketserver as ss
import urllib.parse as parse

HOST, PORT, SITE = 'localhost', 9443, 'qaczar.com'

def receive_post(data: dict) -> str:
    # TODO: Figure out a more robust way to handle post data.
    # TODO: Consider using a database (sqlite3?).
    # TODO: Investigate using blockchain to resolve authority clashes.
    emit(f"Received {data=}.")
    fname = secrets.token_hex(8) + '.txt'
    write_file(wp := work_path(fname), data)
    return wp

def pip_import(module: str) -> t.Any:
    # TODO: Add option to import from a local directory, or specify a version?
    # TODO: Keep a dynamic deny list of modules that are not allowed to be imported.
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError:
        emit(f"Installing {module=}.")
        if '.' in module: module = module.split('.')[0]
        sp.run([sys.executable, '-m', 'pip', 'install', module])
        return importlib.import_module(module)
    
def imports(*modules: tuple[str]) -> t.Callable:
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*(pip_import(module) for module in modules), *args, **kwargs)
        return wrapper
    return decorator

@imports('cryptography.hazmat.primitives.serialization',
    'cryptography.hazmat.primitives.asymmetric.rsa',
    'cryptography.x509',
    'cryptography.hazmat.primitives.hashes')
def get_ssl_certs(ser, rsa, x509, hashes, site=SITE) -> tuple[str, str]:
    # TODO: Figure out if we are the CA.
    if not os.path.exists('.ssl'): os.mkdir('.ssl')
    certname, keyname = '.ssl/cert.pem', '.ssl/key.pem'
    if not os.path.exists(certname) or not os.path.exists(keyname):
        emit("Generating SSL certificates for localhost.")
        # TODO: Use a CA if available.
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
    return certname, keyname

def build_https_server() -> tuple:
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(*get_ssl_certs())
    
    class SSLServer(ss.TCPServer):
        def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
            ss.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
            self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True) 

    class EmitHandler(hs.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            emit(f"Access from {self.address_string()} {format % args}")

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
            if method == 'POST': context['post'] = parse.parse_qs(self.rfile_read())
            else: context['post'] = {}
            return context

        def build_response(self, method: str = None) -> bool:
            # TODO: Change default response depending on the next role of the server.
            path = '/qaczar.html' if self.path == '/' else self.path
            context = self.build_context(path, method)
            self.path = dispatch_processor(path[1:], context)

        def do_HEAD(self) -> None:
            self.build_response('HEAD'); return super().do_HEAD()
            
        def do_GET(self) -> None:
            self.build_response('GET'); return super().do_GET()
        
        def do_POST(self) -> None:
            self.build_response('POST'); return super().do_GET()

    return SSLServer, EmitHandler

def client_request(
        path: str, data: dict = None, host: str = HOST, port: int = PORT) -> tuple:
    # TODO: Test this.
    if path[0] != '/': path = '/' + path
    method = 'POST' if data is not None else 'GET'
    with ss.create_connection((host, port)) as sock:
        with ss.SSLContext().wrap_socket(sock, server_hostname=host) as ssock:
            ssock.sendall(f"{method} {path} HTTP/1.1\r\n".encode())
            ssock.sendall(f"Host: {host}:{port}\r\n".encode())
            if data is not None:
                ssock.sendall("Content-Type: application/x-www-form-urlencoded\r\n".encode())
                ssock.sendall(f"Content-Length: {len(data)}\r\n".encode())
                ssock.sendall("\r\n".encode())
                ssock.sendall(parse.urlencode(data).encode())
            ssock.sendall("\r\n".encode())
            response = ssock.recv(4096).decode()
            status, body = response.split('\r\n\r\n', 1)
            return status, body


#@# 6. COMMON ROLES
# NOTE: All <role>_loop functions must have *args and **kwargs as parameters.

def watcher_loop(*args, next: str = None, opid: str =None, **kwargs) -> t.NoReturn:
    # TODO: Include a mode to watch external processes.
    role = kwargs['role'] = next
    emit(f"Watching over {role=} {opid=} forever.")
    watch_over(start_python(__file__, *args, **kwargs), __file__)

def server_loop(*args, host='localhost', port='9443', **kwargs) -> t.NoReturn:
    # TODO: After the server is ready, figure out what to start next (not the tester).
    # TODO: See if we can use doctest to test the code of _loop functions.
    # TODO: Should we pass extra arguments to the server?
    server_cls, handler_cls = build_https_server()
    with server_cls((host, int(port)), handler_cls) as httpd:
        emit(f"Server ready at https://{host}:{port}")
        atexit.register(httpd.shutdown)
        httpd.serve_forever()

def tester_loop(*args, role: str = None, **kwargs) -> t.NoReturn:
    # doctest.testmod(verbose=True)
    emit(f"Tester done.")
    

def relay_loop(*args, **kwargs: dict) -> t.NoReturn:
    # TODO: Listener that queues requests and forwards them to the server.
    # TODO: Multiple input channels should be supported.
    raise NotImplementedError


if __name__ == "__main__":
    if len(sys.argv) == 1:
        __role, __args, __kwargs = 'watcher', [], {'next': 'server'}
    else:
        __args, __kwargs = split_arg_line(sys.argv[1:])
        __role = __kwargs.pop('role')  # This should never fail.
    emit(f"In watched subprocess role='{__role}' args={__args} kwargs={__kwargs}")
    # TODO: Roles with __ prefix are reserved for internal use.
    # TODO: If the launched role has a test_<role> function, run it.
    set_workdir(__role)
    try:
        locals()[f"{__role}_loop"](*__args, **__kwargs)
    except Exception as e:
        emit(f"Exception in role '{__role}': {e}")
        # Start a tester role to test the code.
        # TODO: See if we should start the tester in a separate process.
        tester_loop(role=__role, args=__args, kwargs=__kwargs)


#@# 7. TESTS
# NOTE: All test_<role> functions must have *args and **kwargs as parameters.

# TODO: Implement our own blockchain for versioning and testing.

def test_server_loop(requests, *args, **kwargs) -> t.NoReturn:
    # See if we can reach the server.
    status, body = client_request('/')
    assert status == 'HTTP/1.0 200 OK'
    # See if we can reach the server with a query string.
    status, body = client_request('/?a=1&b=2')
    assert status == 'HTTP/1.0 200 OK'
    # See if we can reach the server with a POST request.
    status, body = client_request('/', {'a': 1, 'b': 2})
    assert status == 'HTTP/1.0 200 OK'
    # See if we can reach the server with a POST request and a query string.
    status, body = client_request('/?a=1&b=2', {'a': 1, 'b': 2})
    assert status == 'HTTP/1.0 200 OK'
