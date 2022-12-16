#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that experiments with programming paradigms and ideas.
# by R.J. Guillén (rjguillen [at] qaczar.com) 2022

#   GUIDELINES
# - Keep the line width to less than 100 characters.
# - Use functions, not classes, for modularity, composability and encapsulation.
# - Functions should not reference functions or globals from later in the script.
# - TODO items should be encapsulated in functions to simplify refactoring.
# - Avoid using asynchrony, concurrency, multiprocessing, multithreading, etc. Use HTTPS for RPC.
# - Use the standard library, not third-party libraries. Seriously.
# - Sometimes its ok to break the rules, take advantage of the language.
# - In case of doubt, just run the script and see what happens.


#@# LOCAL PLATFORM

import os
import sys
import time
import typing as t

PYTHON = sys.executable
PID = os.getpid()

def iso8601() -> str: 
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str, _at=None) -> None: 
    global PID
    f = _at or sys._getframe(1)  
    print(f'[{PID}:{f.f_lineno} {iso8601()}] {f.f_code.co_name}:  {msg}', file=sys.stderr)

def halt(msg: str) -> t.NoReturn:
    f = sys._getframe(1)
    emit(f"{msg} <- Final message.", _at=f)
    emit(f"Halting all processes.", _at=f)
    sys.exit(0)

def mtime_file(fname: str) -> float:
    if not os.path.isfile(fname): return 0.0
    return os.path.getmtime(fname)

def read_file(fname: str, encoding=None) -> bytes:
    if '__' in fname: fname = fname.replace('__', '.')
    with open(fname, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def write_file(fname: str, data: bytes | str, encoding=None) -> None:
    if encoding and not isinstance(data, str): data = str(data)
    if '__' in fname: fname = fname.replace('__', '.')
    with open(fname, 'wb' if not encoding else 'w', encoding=encoding) as f: f.write(data)


#@# META-PROGRAMMING

import importlib
import functools

DEBUG = False

def dedent(code: str) -> str:
    indent = len(code) - len(code.lstrip()) - 1
    return '\n'.join(line[indent:] for line in code.splitlines())

def timed(f: t.Callable) -> t.Callable:
    global DEBUG
    if not DEBUG: return f
    @functools.wraps(f)
    def timed(*args, **kwargs):
        start = time.time(); elapsed = time.time() - start
        emit(f"Function <{f.__name__}> {args=} {kwargs=} called.")
        result = f(*args, **kwargs)
        emit(f"Function <{f.__name__}> {args=} {kwargs=} took {elapsed:.4f} seconds.")
        return result
    return timed

def pip_import(module: str) -> t.Any:
    try:
        return importlib.import_module(module)
    except ModuleNotFoundError:
        emit(f"Installing {module=}.")
        if '.' in module: module = module.split('.')[0]
        subprocess.run([sys.executable, '-m', 'pip', 'install', module])
        requirements = read_file('requirements.txt', encoding='utf-8')
        if module not in requirements:
            emit(f"Appending {module=} to requirements.txt.")
            write_file('requirements.txt', requirements + 
                f'\n{module}', encoding='utf-8')
        return importlib.import_module(module)

REQUIREMENTS = set()

def imports(*modules: tuple[str]) -> t.Callable:
    global REQUIREMENTS
    for module in modules:
        if '.' in module: module = module.split('.')[0]
        if module not in sys.builtin_module_names: REQUIREMENTS.add(module)
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            return f(*(pip_import(module) for module in modules), *args, **kwargs)
        return wrapper
    return decorator

def write_requirements() -> None:
    global REQUIREMENTS
    if not REQUIREMENTS: return
    emit(f"Writting {len(REQUIREMENTS)} requirements.")
    write_file('requirements.txt', '\n'.join(REQUIREMENTS), encoding='utf-8')


#@# SUBPROCESSING

import shutil
import atexit
import subprocess 

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

def ensure_venv(reset=False) -> None:
    global PYTHON
    if reset and os.path.isdir('.venv'):
        emit(f"Removing {'.venv'} directory.")
        shutil.rmtree('.venv')
    if sys.platform.startswith('win'):
        if not os.path.isfile('.venv/Scripts/python.exe'): 
            subprocess.run([sys.executable, '-m', 'venv', '.venv'])
        PYTHON = '.venv/Scripts/python.exe'
        return
    if not os.path.isfile('.venv/bin/python3'): 
        subprocess.run([sys.executable, '-m', 'venv', '.venv'])
    PYTHON = '.venv/bin/python3'

def start_py(script: str, *args: list[str], **kwargs: dict) -> subprocess.Popen:
    global PYTHON
    line_args = [str(a) for a in arg_line(*args, **kwargs)]
    emit(f"Starting {script=} {line_args=}.")
    # Popen is a context manager, but we want to keep proc alive and not wait for it.
    # We cannot use run() for this. Remember to manually terminate the process later.
    proc = subprocess.Popen([PYTHON, script, *line_args],
                            stdout=sys.stdout, stderr=sys.stderr)
    proc._args, proc._kwargs = args, kwargs  # Magic for restart_python.
    atexit.register(proc.terminate)
    emit(f"Started script='{os.path.basename(script)}' {proc.pid=}.")
    return proc

def stop_py(proc: subprocess.Popen) -> tuple[tuple, dict]:
    emit(f"Stopping {proc.pid=}.")
    proc.terminate(); proc.wait()
    atexit.unregister(proc.terminate)
    return proc._args, proc._kwargs

def restart_py(proc: subprocess.Popen = None, opid=PID) -> subprocess.Popen:
    if proc and proc.poll() is None: 
        args, kwargs = stop_py(proc)
        kwargs['opid'] = opid
    else: args, kwargs = [], {}
    return start_py('qaczar.py', *args, **kwargs)

def watch_over(proc: subprocess.Popen, fn: str) -> t.NoReturn:  
    assert isinstance(proc, subprocess.Popen)
    source, old_mtime, stable = read_file(fn), mtime_file(fn), True
    while True:
        time.sleep(2.6)
        if (new_mtime := mtime_file(fn)) != old_mtime:
            mutation, old_mtime = read_file(fn), new_mtime
            if mutation != source:
                emit(f"Mutation detected. Optimistic restart.")
                proc, stable = restart_py(proc), True
            continue
        if proc.poll() is not None:  # Script terminated.
            if proc.returncode == 0: sys.exit(0)  # Halt from below.
            if stable:
                emit(f"Script died {proc.returncode=}. Restart and mark unstable.")
                proc, stable = restart_py(proc), False
                continue
            halt(f"Script died twice. Stopping watcher.")
        if not stable:
            emit(f"Stabilizing {proc.pid=}.")
            source, stable = read_file(fn), True
            

#@# CONTENT GENERATOR

import io
import xml.etree.ElementTree as etree
from contextlib import redirect_stdout

WORKDIR = os.path.join(os.path.dirname('qaczar.py'), '.work')
TEMPLATES = {}

def set_workdir(role: str) -> None:
    global WORKDIR
    WORKDIR = os.path.join(os.path.dirname('qaczar.py'), f'.{role}')

def work_path(fname: str) -> str:
    global WORKDIR
    if not os.path.isdir(WORKDIR): os.mkdir(WORKDIR)
    return os.path.join(WORKDIR, fname)

def load_template(fname: str) -> str:
    global TEMPLATES
    if (last := mtime_file(fname)) != TEMPLATES.get(fname, (None, None))[1]:
        emit(f"Loading template {fname=}.")
        mt = pip_import('mako.template')
        tpl = mt.Template(filename=fname)
        TEMPLATES[fname] = tpl, last
        return tpl
    return TEMPLATES[fname][0]

def build_form():
    # TODO: New function to automatically create a form from a function.
    pass

def process_html(fname: str, context: dict) -> str:
    template = load_template(fname)
    content = template.render(**globals(), **context)
    write_file(wp := work_path(fname), content, encoding='utf-8')
    emit(f"Written to {wp=} as {fname=} ({len(content)=} bytes).")  
    return wp
    
@timed
def dispatch_processor(fname: str, context: dict) -> str | None:
    if (processor := globals().get(f'process_{fname.split(".")[-1]}')):
        emit(f"Processing {fname=} with <{processor.__name__}>.")
        return processor(fname, context)
    return None


#@# SECURE SERVER

import ssl
import urllib3
import importlib
import datetime as dt
import http.server as hs
import socketserver as ss
import urllib.parse as parse

HOST, PORT, SITE = 'localhost', 9443, 'qaczar.com'

@imports('cryptography.hazmat.primitives.serialization',
    'cryptography.hazmat.primitives.asymmetric.rsa',
    'cryptography.x509',
    'cryptography.hazmat.primitives.hashes')
def get_ssl_certs(ser, rsa, x509, hashes, site=SITE) -> tuple[str, str]:
    if not os.path.exists('.ssl'): os.mkdir('.ssl')
    certname, keyname = '.ssl/cert.pem', '.ssl/key.pem'
    if not os.path.exists(certname) or not os.path.exists(keyname):
        emit("Generating SSL certificates for localhost.")
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
            context = {'ip': self.client_address[0], 'ts': iso8601(), 'method': method}
            context['query'] = parse.parse_qs(qs)
            if method == 'POST': context['form'] = parse.parse_qs(self.rfile_read())
            else: context['form'] = {}
            return context

        def build_response(self, method: str = None) -> bool:
            self.path = '/qaczar.html' if self.path == '/' else self.path
            context = self.build_context(self.path, method)
            self.work_path = dispatch_processor(self.path[1:], context)
            emit(f"{context['ip']} {context['ts']} {method} {self.path} ({self.work_path})")
            
        def translate_path(self, path: str = None) -> str:
            return super().translate_path(path) if not self.work_path else self.work_path

        def do_HEAD(self) -> None:
            self.build_response('HEAD'); return super().do_HEAD()
            
        def do_GET(self) -> None:
            self.build_response('GET'); return super().do_GET()
        
        def do_POST(self) -> None:
            self.build_response('POST'); return super().do_GET()

    return SSLServer, EmitHandler


#@#  SELF TESTING

@imports('requests')
def test_server(requests, *args, **kwargs) -> t.NoReturn:
    # Use the self-signed certificate to verify the server
    http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED',
        ca_certs=get_ssl_certs()[0])
    def server_request(fname:str):
        r = requests.get(url := f"https://{HOST}:{PORT}/{fname}", verify=False)
        emit(f"Server response: {url=} {r.status_code} {r.reason}")
        if r.status_code != 200: 
            raise ValueError(f"Error response: {r.status_code} {r.reason}")
        return r.text
    server_request('qaczar.html')
    server_request('qaczar.py')
    server_request('qaczar.css')


#@#  REPOSITORY

def commit_source() -> t.NoReturn:
    write_requirements()
    emit("Commiting source to repository.")
    os.system('git add .')
    os.system('git commit -m "auto commit"')
    os.system('git push')


#@# COMMON ROLES

def watcher_role(*args, next: str = None, **kwargs) -> t.NoReturn:
    if not next: raise ValueError('next role was not defined')
    kwargs['role'] = next
    watch_over(start_py('qaczar.py', *args, **kwargs), 'qaczar.py')

def server_role(*args, host='localhost', port='9443', **kwargs) -> t.NoReturn:
    server_cls, handler_cls = build_https_server()
    with server_cls((host, int(port)), handler_cls) as httpd:
        emit(f"Server ready at https://{host}:{port}")
        atexit.register(httpd.shutdown)
        kwargs['role'] = 'tester'
        kwargs['suite'] = 'server' if 'suite' not in kwargs else kwargs['suite']
        start_py('qaczar.py', *args, **kwargs)
        httpd.serve_forever()

def tester_role(*args, suite: str = None, **kwargs) -> t.NoReturn:
    # TODO: Use tests to prevent regressions (loss of functionality)
    emit(f"Running tests for {suite}.")
    for test in globals().keys():
        if test == f'test_{suite}': 
            emit(f"Running {test=}...")
            globals()[test](*args, **kwargs)
    emit(f"Tests for {suite} passed.")
    commit_source()


#@# DISPATCHER

def role_dispatcher(role: str, args: tuple, kwargs: dict) -> None:
    import threading
    opid = kwargs.pop('opid', None)  # If we receive opid it means we are being watched.
    emit(f"Assuming role='{__role}' args={__args} kwargs={__kwargs} watch by {opid=}.")
    def dispatch():
        function = globals().get(f"{role}_role")
        if function is None: raise ValueError(f"Role '{role}' is not defined.")
        function(*args, **kwargs)
    threading.Thread(target=dispatch, daemon=True).start()
    # We can do other stuff here, like launching another role.
    while threading.active_count() > 1: time.sleep(1)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        __role, __args, __kwargs = 'watcher', [], {'next': 'server'}
        reset = True
    else:
        __args, __kwargs = split_arg_line(sys.argv[1:])
        __role = __kwargs.pop('role')  # It's ok to fail if role is not defined.
        reset = False
    ensure_venv(reset=reset)
    set_workdir(__role)
    DEBUG = True if 'debug' in __args else DEBUG
    role_dispatcher(__role, __args, __kwargs)
