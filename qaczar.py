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
DEBUG = False  

def iso8601() -> str: 
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str, _at=None) -> None: 
    global PID
    frame = _at or sys._getframe(1)  
    print(f'[{PID}:{frame.f_lineno} {iso8601()}] {frame.f_code.co_name}:  {msg}', file=sys.stderr)

def halt(msg: str) -> t.NoReturn:
    frame = sys._getframe(1)
    emit(f"{msg} <- Final message.", _at=frame)
    emit(f"Halting all processes.", _at=frame)
    sys.exit(0)

def _mtime_file(fname: str) -> float:
    if not os.path.isfile(fname): return 0.0
    return os.path.getmtime(fname)

def read_file(fname: str, encoding=None) -> bytes:
    if '__' in fname: fname = fname.replace('__', '.')
    with open(fname, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def _write_file(fname: str, data: bytes | str, encoding=None) -> str:
    if encoding and not isinstance(data, str): data = str(data)
    if '__' in fname: fname = fname.replace('__', '.')
    parent_dir = os.path.dirname(fname)
    if parent_dir and not os.path.isdir(parent_dir): os.makedirs(parent_dir)
    with open(fname, 'wb' if not encoding else 'w', encoding=encoding) as f: f.write(data)
    return fname


#@# META-PROGRAMMING

import importlib
import functools

def dedent(code: str) -> str:
    indent = len(code) - len(code.lstrip()) - 1
    return '\n'.join(line[indent:] for line in code.splitlines())

def timed(f: t.Callable) -> t.Callable:
    global DEBUG
    if not DEBUG: return f
    @functools.wraps(f)
    def _timed(*args, **kwargs):
        start = time.time(); elapsed = time.time() - start
        result = f(*args, **kwargs)
        emit(f"Function <{f.__name__}> {args=} {kwargs=} took {elapsed:.4f} seconds.")
        return result
    return _timed

def _pip_import(module: str) -> t.Any:
    name = module.split('.')[0]
    requirements = read_file('requirements.txt', encoding='utf-8').splitlines()
    if name not in requirements:    
        subprocess.run([sys.executable, '-m', 'pip', 'install', name, '--quiet'])
        with open('requirements.txt', 'a', encoding='utf-8') as f: f.write(f'{name}\r\n')
    return importlib.import_module(module)

def imports(*modules: tuple[str]) -> t.Callable:
    # TODO: Allow specifying a version number (important for self-recovery).
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            imported = [_pip_import(module) for module in modules]
            return f(*imported, *args, **kwargs)
        return wrapper
    return decorator

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


#@# SUBPROCESSING

import shutil
import atexit
import subprocess 

def _setup_environ(reset=False) -> None:
    global PYTHON
    # TODO: Add qaczar itself (edit mode?) to a new requirements.txt file.
    if not os.path.isfile('requirements.txt'): 
        _write_file('requirements.txt', '', encoding='utf-8')
    if reset and os.path.isdir('.venv'):
        emit(f"Removing {'.venv'} directory.")
        shutil.rmtree('.venv')
    if sys.platform.startswith('win'):
        if not os.path.isfile('.venv/Scripts/python.exe'): 
            subprocess.run([sys.executable, '-m', 'venv', '.venv'])
        PYTHON = '.venv/Scripts/python.exe'
    elif not os.path.isfile('.venv/bin/python3'): 
        subprocess.run([sys.executable, '-m', 'venv', '.venv'])
        PYTHON = '.venv/bin/python3'
    subprocess.run([PYTHON, '-m', 'pip', 'install', '--upgrade', 'pip'])

def _start_py(script: str, *args: list[str], **kwargs: dict) -> subprocess.Popen:
    global PYTHON
    line_args = [str(a) for a in arg_line(*args, **kwargs)]
    emit(f"Starting {script=} {line_args=}.")
    # Popen is a context manager, but we want to keep proc alive and not wait for it.
    # We cannot use run() for this. Remember to manually terminate the process later.
    proc = subprocess.Popen([PYTHON, script, *line_args],
                            stdout=sys.stdout, stderr=sys.stderr)
    proc._args, proc._kwargs = args, kwargs  # Magic for restart_python.
    atexit.register(proc.terminate)
    return proc

def _stop_py(proc: subprocess.Popen) -> tuple[tuple, dict]:
    emit(f"Stopping {proc.pid=}.")
    proc.terminate(); proc.wait()
    atexit.unregister(proc.terminate)
    return proc._args, proc._kwargs

def _restart_py(proc: subprocess.Popen = None, opid=PID) -> subprocess.Popen:
    if proc and proc.poll() is None: 
        args, kwargs = _stop_py(proc)
        kwargs['opid'] = opid
    else: args, kwargs = [], {}
    return _start_py('qaczar.py', *args, **kwargs)

def _watch_over(proc: subprocess.Popen, fn: str) -> t.NoReturn:  
    assert isinstance(proc, subprocess.Popen)
    source, old_mtime, stable = read_file(fn), _mtime_file(fn), True
    while True:
        time.sleep(2.6)
        if (new_mtime := _mtime_file(fn)) != old_mtime:
            mutation, old_mtime = read_file(fn), new_mtime
            if mutation != source:
                emit(f"Mutation detected. Optimistic restart.")
                proc, stable = _restart_py(proc), True
            continue
        if proc.poll() is not None:  # Script terminated.
            if proc.returncode == 0: sys.exit(0)  # Halt from below.
            if stable:
                emit(f"Script died {proc.returncode=}. Restart and mark unstable.")
                proc, stable = _restart_py(proc), False
                continue
            halt(f"Script died twice. Stopping watcher.")
        if not stable:
            emit(f"Stabilizing {proc.pid=}.")
            source, stable = read_file(fn), True
            

#@# CONTENT GENERATOR

import inspect

WORKDIR = os.path.join(os.path.dirname('qaczar.py'), '.work')
TEMPLATES = {}

def _set_workdir(role: str) -> None:
    global WORKDIR
    WORKDIR = os.path.join(os.path.dirname('qaczar.py'), f'.{role}')

def _work_path(fname: str) -> str:
    global WORKDIR
    if not os.path.isdir(WORKDIR): os.mkdir(WORKDIR)
    return os.path.join(WORKDIR, fname)

def write_file(fname: str, content: str) -> str:
    return _write_file(_work_path(fname), content, encoding='utf-8')

def _load_template(fname: str) -> str:
    global TEMPLATES
    if (last := _mtime_file(fname)) != TEMPLATES.get(fname, (None, None))[1]:
        mt = _pip_import('mako.template')
        tpl = mt.Template(filename=fname)
        TEMPLATES[fname] = tpl, last
        return tpl
    return TEMPLATES[fname][0]

def process_html(fname: str, context: dict) -> str:
    template = _load_template(fname)
    content = template.render(**globals(), **context)
    return write_file(fname, content)

def _extract_api(module) -> t.Generator[t.Callable, None, None]:
    for name, func in inspect.getmembers(module, inspect.isfunction):
        if name.startswith('_'): continue
        if inspect.signature(func).return_annotation in (t.NoReturn, t.Callable): continue
        yield func

def _module_name(module) -> str:
    return module.__name__ if module.__name__ != '__main__' else 'qaczar'

def function_index(module = None) -> str:
    if module is None: module = sys.modules[__name__]
    mod_name = _module_name(module)
    return '\n'.join(
            f"<li><a href='{mod_name}.py/{fn.__name__}'>{fn.__name__}</a></li>" 
            for fn in _extract_api(module))

def _build_form(module, subpath: str) -> str:
    # TODO: Handle multiple subpaths by using fieldsets.
    # TODO: Consider using type annotations to determine the input type.
    # TODO: Add function name, description, and docstring.
    # TODO: Functions with cache decorator should just be invoked?
    func = getattr(module, subpath)
    sig = inspect.signature(func)
    form = (f"<form action='/{ _module_name(module)}.py/{subpath}' "
            f"method='POST' accept-charset='utf-8' name='{subpath}'>" \
            f"<link rel='stylesheet' href='/qaczar.css'>"
            f"<h3>{subpath.upper()}</h3>")
    for name, param in sig.parameters.items():
        if param.kind == param.VAR_KEYWORD: continue
        if name.startswith('_'): continue
        form += f"<label for='{name}'>{name.upper()} : </label>"
        if param.kind == param.VAR_POSITIONAL:
            form += f"<input type='text' name='{name}' value='[]'>"
        elif param.default is param.empty:
            form += f"<input type='text' name='{name}'>"
        else:
            form += f"<input type='text' name='{name}' value='{param.default}'>"
        form += f"<br>"
    submit_label = func.__name__.replace('_', ' ').upper()
    form += f"<button type='submit'>{submit_label}</button></form>"
    return form

def process_py(fname: str, context: dict) -> str:
    # GET returns a form for a function (or list of functions),
    # POST executes them and returns the result as hypermedia.
    if (subpath := context.get('subpath', None)) is None: return fname
    module = importlib.import_module(fname[:-3])
    outname = f"{_module_name(module)}.{subpath}.html" 
    method = context.get('method', 'GET')
    if method == 'GET':
        form = _build_form(module, subpath)
        return write_file(outname, form)
    elif method == 'POST':
        func = getattr(module, subpath)
        result = func(**context['data'])
        return write_file(outname, result)
    
@timed
def _dispatch_processor(fname: str, context: dict) -> str | None:
    prefix, suffix = fname.split(".", 1)  # Only one dot is allowed.
    if '/' in suffix: 
        suffix, subpath = suffix.split('/')
        context['subpath'] = subpath
    if (processor := globals().get(f'process_{suffix}')):
        return processor(f'{prefix}.{suffix}', context)
    return None


#@# POST RECEIVERS

def hello_world(*args, **kwargs) -> str:
    return "Hello, world!"


#@# HTTPS SERVER

import ssl
import importlib
import datetime as dt
import http.server as hs
import socketserver as ss
import urllib.parse as parse

HOST, PORT, SITE = 'localhost', 9443, 'qaczar.com'

@imports('cryptography.x509',
    'cryptography.hazmat.primitives.asymmetric.rsa',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.primitives.serialization')
def _get_ssl_certs(x509, rsa, hashes, ser, site=HOST) -> tuple[str, str]:
    if not os.path.exists('.ssl'): os.mkdir('.ssl')
    certname, keyname = '.ssl/cert.pem', '.ssl/key.pem'
    if os.path.exists(certname) and os.path.exists(keyname):
        cert = x509.load_pem_x509_certificate(read_file(certname))
        if cert.not_valid_after > dt.datetime.utcnow(): return certname, keyname
        else: os.remove(certname); os.remove(keyname)
    emit("Generating new SSL certificates for localhost.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write_file(keyname, key.private_bytes(
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
    _write_file(certname, cert.public_bytes(ser.Encoding.PEM))
    return certname, keyname

def _build_https_server() -> tuple:
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(*_get_ssl_certs())
    
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
            if method == 'POST': context['data'] = parse.parse_qs(self.rfile_read())
            else: context['data'] = {}
            return context

        def build_response(self, method: str = None) -> bool:
            self.path = '/qaczar.html' if self.path == '/' else self.path
            context = self.build_context(self.path, method)
            self.work_path = _dispatch_processor(self.path[1:], context)
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

@imports('urllib3')
def test_server(urllib3, *args, **kwargs) -> t.NoReturn:
    http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED',
        ca_certs=_get_ssl_certs()[0])
    
    def server_request(fname:str):
        r = http.request('GET', url := f"https://{HOST}:{PORT}/{fname}", timeout=30)
        emit(f"Server response: {url=} {r=}")
        if r.status != 200: raise ValueError(f"Unexpected response: {r.status} {r.reason}")
        return r.data.decode('utf-8')
    
    assert 'QACZAR' in server_request('qaczar.html')
    assert 'QACZAR' in server_request('qaczar.py')


#@#  REPOSITORY

def _commit_source() -> t.NoReturn:
    os.system('git add .')
    os.system('git commit -m "auto commit"')
    os.system('git push')
    emit("Source committed to repository.")


#@# COMMON ROLES

def watcher_role(*args, next: str = None, **kwargs) -> t.NoReturn:
    if not next: raise ValueError('next role was not defined')
    kwargs['role'] = next
    _watch_over(_start_py('qaczar.py', *args, **kwargs), 'qaczar.py')

def server_role(*args, host='localhost', port='9443', **kwargs) -> t.NoReturn:
    server_cls, handler_cls = _build_https_server()
    with server_cls((host, int(port)), handler_cls) as httpd:
        emit(f"Server ready at https://{host}:{port}")
        atexit.register(httpd.shutdown)
        kwargs['role'] = 'tester'
        kwargs['suite'] = 'server' if 'suite' not in kwargs else kwargs['suite']
        _start_py('qaczar.py', *args, **kwargs)
        httpd.serve_forever()

def tester_role(*args, suite: str = None, **kwargs) -> t.NoReturn:
    # TODO: Use tests to prevent regressions (loss of functionality)
    emit(f"Running tests for {suite}.")
    for test in globals().keys():
        if test == f'test_{suite}': 
            emit(f"Running {test=}...")
            globals()[test](*args, **kwargs)
    emit(f"Tests for {suite} passed.")
    _commit_source()


def deployer_role(*args, **kwargs) -> t.NoReturn:
    pass


#@# DISPATCHER

def _role_dispatcher(role: str, args: tuple, kwargs: dict) -> t.NoReturn:
    # TODO: Consider using tomlib for configuration.
    import threading
    _set_workdir(role)
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
    _setup_environ(reset=reset)
    DEBUG = True if 'debug' in __args else DEBUG
    _role_dispatcher(__role, __args, __kwargs)
