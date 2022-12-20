#!/usr/bin/env python
# -*- coding: utf-8 -*-

# qaczar.py: An Hymn to the Self-Inventing.
# by R. G. Osorio (rgo [at] qaczar [dot] com) 2022.
# License: MIT (https://opensource.org/licenses/MIT).

# + A few guidelines for editing this script:
# - Keep the line width to less than 100 characters. Aesthetics matter, but not too much.
# - Prefer functions, instead of classes, for modularity, composability and encapsulation.
# - Functions should not reference functions or other globals defined later in the script.
# - Avoid using asynchrony, concurrency, multiprocessing, multithreading, etc. Use HTTPS for RPC.
# - Exploit the limits of the standard library, avoid third-party dependencies.
# - Sometimes, its ok to break the rules: take advantage of the language but clean up after.
# - In case of doubt, play the game to see what happens. Also, you just lost it.


#@# LOCAL PLATFORM

import os
import sys
import time
import typing as t

_PYTHON = sys.executable
_PID = os.getpid()
_DEBUG = True  
_BRANCH = 'main'
_DIR = os.path.dirname(os.path.abspath(__file__))

APP = os.path.basename(_DIR)

def iso8601() -> str: 
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str, _at=None) -> None: 
    global _PID
    frame = _at or sys._getframe(1)  
    print(f'[{_PID}:{frame.f_lineno} {iso8601()}] {frame.f_code.co_name}:  {msg}', file=sys.stderr)

def halt(msg: str) -> t.NoReturn:
    frame = sys._getframe(1)
    emit(f"{msg} <- Final message.", _at=frame)
    emit(f"Halting all processes.", _at=frame)
    sys.exit(0)

def _mtime_file(fname: str) -> float:
    if not os.path.isfile(fname): return 0.0
    return os.path.getmtime(fname)

def _read_file(fname: str, encoding=None) -> bytes:
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
    global _DEBUG
    if not _DEBUG: return f
    @functools.wraps(f)
    def _timed(*args, **kwargs):
        start = time.time(); elapsed = time.time() - start
        result = f(*args, **kwargs)
        emit(f"Function <{f.__name__}> {args=} {kwargs=} took {elapsed:.4f} seconds.")
        return result
    return _timed

def _pip_import(module: str) -> t.Any:
    name = module.split('.')[0]
    requirements = _read_file('requirements.txt', encoding='utf-8').splitlines()
    if name not in requirements:    
        subprocess.run([sys.executable, '-m', 'pip', 'install', name, '--quiet'])
        with open('requirements.txt', 'a', encoding='utf-8') as f: f.write(f'{name}\n')
    return importlib.import_module(module)

def imports(*modules: tuple[str]) -> t.Callable:
    """Decorator to import modules at runtime, passing them as arguments."""
    # TODO: Allow specifying version number in runtime imports (for self-remediation).
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

import atexit
import subprocess 

def _setup_environ() -> None:
    global _PYTHON
    if not os.path.isfile('requirements.txt'): 
        _write_file('requirements.txt', '', encoding='utf-8')
    if sys.platform.startswith('win'):
        if not os.path.isfile('.venv/Scripts/python.exe'): 
            subprocess.run([sys.executable, '-m', 'venv', '.venv'])
        _PYTHON = '.venv/Scripts/python.exe'
    elif not os.path.isfile('.venv/bin/python3'): 
        subprocess.run([sys.executable, '-m', 'venv', '.venv'])
        _PYTHON = '.venv/bin/python3'
    subprocess.run([_PYTHON, '-m', 'pip', 'install', '--upgrade', 'pip', '--quiet'])
    subprocess.run([_PYTHON, '-m', 'pip', 'install', '-r', 'requirements.txt'])

def _start_py(script: str, *args: list[str], **kwargs: dict) -> subprocess.Popen:
    global _PYTHON
    line_args = [str(a) for a in arg_line(*args, **kwargs)]
    emit(f"Starting {script=} {line_args=}.")
    # Popen is a context manager, but we want to keep proc alive and not wait for it.
    # We cannot use run() for this. Remember to manually terminate the process later.
    proc = subprocess.Popen([_PYTHON, script, *line_args],
                            stdout=sys.stdout, stderr=sys.stderr)
    proc._args, proc._kwargs = args, kwargs  # Magic for restart_py
    atexit.register(proc.terminate)
    return proc

def _stop_py(proc: subprocess.Popen) -> tuple[tuple, dict]:
    emit(f"Stopping {proc.pid=}.")
    proc.terminate(); proc.wait()
    atexit.unregister(proc.terminate)
    return proc._args, proc._kwargs

def _restart_py(proc: subprocess.Popen = None, opid=_PID) -> subprocess.Popen:
    global APP
    if proc and proc.poll() is None: 
        args, kwargs = _stop_py(proc)
        kwargs['opid'] = opid
    else: args, kwargs = [], {}
    return _start_py(f'{APP}.py', *args, **kwargs)

def _watch_over(proc: subprocess.Popen, fn: str) -> t.NoReturn:  
    assert isinstance(proc, subprocess.Popen)
    source, old_mtime, stable = _read_file(fn), _mtime_file(fn), True
    while True:
        time.sleep(2.6)
        if (new_mtime := _mtime_file(fn)) != old_mtime:
            mutation, old_mtime = _read_file(fn), new_mtime
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
            source, stable = _read_file(fn), True
            

#@# CONTENT GENERATOR

import inspect
import traceback

_WORKDIR = os.path.join(_DIR, '.work')
_TEMPLATES = {}

def _set_workdir(role: str) -> None:
    global _DIR, _WORKDIR
    _WORKDIR = os.path.join(_DIR, f'.{role}')

def _work_path(fname: str) -> str:
    global _WORKDIR
    if not os.path.isdir(_WORKDIR): os.mkdir(_WORKDIR)
    return os.path.join(_WORKDIR, fname)

def read_file(fname: str) -> str:
    """Read a file from the active work folder."""
    return _read_file(_work_path(fname), encoding='utf-8')

def write_file(fname: str, content: str) -> str:
    """Write a file to the active work folder."""
    return _write_file(_work_path(fname), content, encoding='utf-8')

def enum_file(fname: str, tag: str = 'li', prefix: str = None) -> str:
    """Enumerate lines in a file, optionally filtering by prefix."""
    return ''.join(f'<{tag} data-ln="{i}">{line if not prefix else line.split(prefix)[1]}</{tag}>'
        for i, line in enumerate(_read_file(fname, encoding='utf-8').splitlines())
        if not prefix or line.strip().startswith(prefix))

def list_dir(directory: str = '.', tag: str = 'li', ext: str = None, link: bool = True) -> str:
    """List files in a directory, optionally filtering by extension."""
    return '\n'.join(
        f'<{tag}>{f}</{tag}>' if not link else f'<{tag}><a href="/{f}">{f}</a></{tag}>'
        for f in os.listdir(directory)
        if (not ext or f.endswith(ext)) and not f.startswith(('.', '_')))

def _load_template(fname: str) -> str:
    global _TEMPLATES, _DIR
    if (last := _mtime_file(fname)) != _TEMPLATES.get(fname, (None, None))[1]:
        mt = _pip_import('mako.template')
        ml = _pip_import('mako.lookup')
        lookup = ml.TemplateLookup(directories=[_DIR], input_encoding='utf-8')
        tpl = mt.Template(filename=fname, lookup=lookup)
        _TEMPLATES[fname] = tpl, last
        emit(f"Loaded {fname=} {last=}.")
        return tpl
    return _TEMPLATES[fname][0]

@functools.cache
def _safe_globals() -> dict:
    return {k: v for k, v in globals().items() if not k.startswith('_')}

def process_html(fname: str, context: dict) -> str:
    """Process a template file with context (uses mako.template)."""	
    template = _load_template(fname)
    content = template.render(**_safe_globals(), **context)
    return write_file(fname, content)

def extract_api() -> t.Generator[t.Callable, None, None]:
    """Extract all public functions from a module."""
    for name, func in inspect.getmembers(sys.modules[__name__], inspect.isfunction):
        if name.startswith('_') or not func.__doc__: continue
        if inspect.signature(func).return_annotation in (t.NoReturn, t.Callable): continue
        yield func

def function_index() -> str:
    """Generate a list of links to all public functions in a module."""
    global APP
    return '\n'.join(f"<li><a href='{APP}.py/{fn.__name__}'>{fn.__name__}</a></li>" 
            for fn in extract_api())

def _build_input(field: str, param: inspect.Parameter) -> str:
    input_type = 'text'
    if param.annotation is not param.empty:
        if param.annotation is int: input_type = 'number'
        elif param.annotation is bool: input_type = 'checkbox'
    if param.default is param.empty or param.default is None:
        return f"<input type='{input_type}' name='{field}'>"
    return f"<input type='{input_type}' name='{field}' value='{param.default}'>"

def _active_module(mod_name: str):
    return sys.modules[mod_name if mod_name != APP else __name__]

@functools.cache
def _build_form(mod_name: str, subpath: str) -> str:
    # TODO: Handle multiple subpaths by using fieldsets? Allow decorators?
    func = getattr(_active_module(mod_name), subpath)
    form = (f"<form action='/{mod_name}.py/{subpath}' "
            f"method='POST' accept-charset='utf-8' name='{subpath}'>" 
            f"<link rel='stylesheet' href='/qaczar.css'>"
            f"<h3>{subpath.upper()} @ {mod_name.upper()}</h3>"
            f"<p class='doc'>{func.__doc__}</p>")
    for name, param in inspect.signature(func).parameters.items():
        if not param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD): continue
        if name.startswith('_'): continue
        if param.annotation is param.empty: continue
        form += f"<label for='{name}'>{name.upper()}:</label>"
        form += _build_input(name, param) + "<br>"
    form += f"<button type='submit'>EXECUTE</button></form>"
    return write_file(f"{mod_name}__{subpath}.html" , form)

def _execute_form(mod_name: str, subpath: str, data: dict) -> str:
    func = getattr(_active_module(mod_name), subpath)
    if all(len(v) == 1 for v in data.values()):
        data = {k: v[0] for k, v in data.items()}
    result = func(**data)
    if isinstance(result, str): result = f"<pre>{result}</pre>"
    return write_file(f"{mod_name}__{subpath}.html", result)

def process_py(fname: str, context: dict) -> str:
    """Allows extracting or executing functions from a python module.
    A subpath is the name of the function to extract or execute and comes from the context.
    If subpath is not specified, the entire module is extracted and rendered as HTML.
    """
    if (subpath := context.get('subpath', None)) is None: return fname
    mod_name = fname.split('.')[0]
    method = context.get('method', 'GET')
    if method == 'GET':
        return _build_form(mod_name, subpath)
    elif method == 'POST':
        data = context.get('data', {})
        return _execute_form(mod_name, subpath, data)

def create_app(directory: str) -> None:
    """Create a new application using SEEDS from qaczar.py."""
    # TODO: The directory is not being created. Fix this.
    seeds = {
        "html": r"<%inherit file='/qaczar.html'/>", 
        # TODO: Figure what other files are needed for seeding an app.
    }
    if not os.path.exists(directory): 
        emit(f"Create new app directory: {directory}")
        os.mkdir(directory)
    for ext, content in seeds.items():
        write_file(f'{directory}/{directory}.{ext}', content)
    else: emit(f"Skip existing application: {directory}")
    return f'{directory}/{directory}.html'

def _process_error(fname: str, context: dict) -> str:
    """Handle errors by returning a custom 404 page."""
    if '.' in fname: fname = fname.split('.', 1)[0] + '.html'
    err = context.get('error', None)
    banner = ascii_banner(f"404")
    # Include the full traceback in the error page.
    content = (f"<h1><pre>{banner}</pre></h1><p>Not found: {fname}</p><p>{err}</p>"
                f"Traceback:<pre>{traceback.format_exc()}</pre>"
               f"<p><a href='/'>Home</a></p>"
               f'<link rel="stylesheet" href="/qaczar.css">')
    return write_file(fname, content)

@timed
def _dispatch_processor(fname: str, context: dict) -> str | None:
    if '.' not in fname: 
        prefix, suffix = f'{fname}/{fname}', 'html'
        fname = f'{prefix}.{suffix}'
        if not os.path.exists(fname): create_app(fname)
    else: prefix, suffix = fname.split(".", 1)  # Only one dot is allowed.
    if not prefix: return None  # Prevent dotfiles from being processed.
    if '/' in suffix: 
        suffix, subpath = suffix.split('/')
        context['subpath'] = subpath
    if (processor := globals().get(f'process_{suffix}')):
        try:
            return processor(f'{prefix}.{suffix}', context)
        except Exception as e:
            emit(f"Error processing {fname}: {e}")
            context['error'] = e
            return _process_error(fname, context)
    return None


#@# DATABASE

import sqlite3

_SCHEMA = ''

def _init_table(db, table: str, *cols) -> None:
    global _SCHEMA
    sql = (f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols)}, " 
            f"ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP)")
    _SCHEMA += f'{sql};\n'
    db.execute(sql)

def _insert(db, table: str, *values) -> None:
    sql = (f"INSERT INTO {table} VALUES " 
            f"({', '.join('?' * len(values))}, CURRENT_TIMESTAMP)")
    try:
        db.execute(sql, values)
    except Exception as e:
        emit(f"Error on SQL: {sql} with values: {values}")
        e.args = (f"{e.args[0]}: \n{sql}",) + e.args[1:]
        raise e

def recorded(func: t.Callable) -> t.Callable:
    """Decorator to record function calls and results in a database."""
    # TODO: Handle database errors and schema changes.
    func_name = func.__name__
    with _connect_db() as db:
        _init_table(db, f"{func_name}__params", "arg_line TEXT")
        _init_table(db, f"{func_name}__result", "result TEXT", "params_id INTEGER")
    @functools.wraps(func)
    def _recorded(*args, **kwargs):
        with _connect_db() as db:
            _insert(db, f'{func_name}__params', ' '.join(arg_line(*args, **kwargs)))
            result = func(*args, **kwargs)
            emit(f"{func_name}({arg_line(*args, **kwargs)}) -> {result}")
            _insert(db, f'{func_name}__result', result, db.lastrowid)
            db.commit()
        return result
    return _recorded

_DB = None

def _connect_db() -> sqlite3.Connection:
    global APP, _DB
    if _DB is not None: return _DB
    _DB = sqlite3.connect(f'{APP}.sqlite3')
    _DB.execute("CREATE TABLE IF NOT EXISTS apps (name TEXT, ts TEXT)")
    _DB.execute("INSERT INTO apps VALUES (?, ?)", (APP, iso8601()))
    _DB.commit()
    return _DB


#@# WEB COMPONENTS

import random

def page_title(title: str = '') -> str:
    return title if title else f'{APP.upper()}'

@imports('pyfiglet')
def ascii_banner(pyfiglet, text:str) -> str:
    """Generate a banner from ASCII text."""
    fonts = pyfiglet.FigletFont.getFonts()
    font = random.choice(fonts)
    return pyfiglet.figlet_format(text, font=font)


#@# FORM RECEIVERS

@recorded
def hello_world(name: str = 'World', wrapped: bool=True) -> str:
    """Say hello to the world! Useful as a smoke test."""
    if wrapped:
        return f"<div class='hello'>Hello, {name}!</div>"
    return f"Hello, {name}!"

@recorded
def collect_contact(email: str, message: str) -> str:
    # TODO: Consider field validation decorators for POST receiver functions.
    emit(f"Contact from {email}: {message}")
    return f"Thanks for contacting us, {email}!"
    

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
def _get_ssl_certs(x509, rsa, hashes, ser, site=None) -> tuple[str, str]:
    global HOST, SITE
    if site is None: site = HOST if HOST == 'localhost' else SITE
    if not os.path.exists('.ssl'): os.mkdir('.ssl')
    certname, keyname = '.ssl/cert.pem', '.ssl/key.pem'
    if os.path.exists(certname) and os.path.exists(keyname):
        cert = x509.load_pem_x509_certificate(_read_file(certname))
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
            # TODO: Log accesses to DB for analysis and design of the caching model.
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
            self.path = '' if self.path == '/' else self.path
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
    global APP, HOST, PORT
    http = urllib3.PoolManager(
        cert_reqs='CERT_REQUIRED',
        ca_certs=_get_ssl_certs()[0])
    
    def server_request(fname:str):
        r = http.request('GET', url := f"https://{HOST}:{PORT}/{fname}", timeout=30)
        emit(f"Server response: {url=} {r=}")
        if r.status != 200: raise ValueError(f"Unexpected response: {r.status} {r.reason}")
        return r.data.decode('utf-8')
    
    assert 'qaczar' in server_request(f'{APP}.html')
    assert 'qaczar' in server_request(f'{APP}.py')


#@#  REPOSITORY

def _commit_source() -> t.NoReturn:
    # TODO: Create missing branch if not exists when pushing to git.
    global _BRANCH
    os.system('git add .')
    os.system('git commit -m "auto commit"')
    os.system(f'git push origin {_BRANCH}')
    emit(f"Source committed to {_BRANCH}.")


#@# COMMON ROLES

def watcher_role(*args, next: str = None, **kwargs) -> t.NoReturn:
    global APP
    if not next: raise ValueError('next role was not defined')
    kwargs['role'] = next
    _watch_over(_start_py(f'{APP}.py', *args, **kwargs), f'{APP}.py')

def server_role(*args, host=HOST, port=PORT, **kwargs) -> t.NoReturn:
    global APP
    server_cls, handler_cls = _build_https_server()
    with server_cls((host, int(port)), handler_cls) as httpd:
        emit(f"Server ready at https://{host}:{port}")
        atexit.register(httpd.shutdown)
        kwargs['role'] = 'tester'
        kwargs['suite'] = 'server' if 'suite' not in kwargs else kwargs['suite']
        _start_py(f'{APP}.py', *args, **kwargs)
        httpd.serve_forever()

def tester_role(*args, suite: str = None, **kwargs) -> t.NoReturn:
    # TODO: Add some automatic tests to prevent public API regressions.
    emit(f"Running tests for {suite}.")
    for test in globals().keys():
        if test == f'test_{suite}': 
            emit(f"Running {test=}...")
            globals()[test](*args, **kwargs)
    emit(f"Tests for {suite} passed.")
    _commit_source()

def worker_role(*args, **kwargs) -> t.NoReturn:
    pass


#@# DISPATCHER

def _role_dispatcher(role: str, args: tuple, kwargs: dict) -> t.NoReturn:
    _set_workdir(role)
    opid = kwargs.pop('opid', None)  # If we receive opid it means we are being watched.
    emit(f"Assuming role='{__role}' args={__args} kwargs={__kwargs} watch by {opid=}.")
    function = globals().get(f"{role}_role")
    if function is None: raise ValueError(f"Role '{role}' is not defined.")
    function(*args, **kwargs)

if __name__ == "__main__":
    if len(sys.argv) == 1:
        _setup_environ()
        __role, __args, __kwargs = 'watcher', [], {'next': 'server'}
    else:
        __args, __kwargs = split_arg_line(sys.argv[1:])
        __role = __kwargs.pop('role')  # It's ok to fail if role is not defined.
    _DEBUG = True if 'debug' in __args else _DEBUG
    _role_dispatcher(__role, __args, __kwargs)
