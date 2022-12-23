#!/usr/bin/env python
# -*- coding: utf-8 -*-

# qaczar.py: An Hymn to the Self-Inventing, the Celestial Ladder of Web Systems.
# by R. J. Guillén-Osorio (r [at] qaczar [dot] com) 2022-2023.

# License: MIT (https://opensource.org/licenses/MIT).

#   Coding Guidelines:
# 1 One Script. Keep line width to less than 100 characters. Aesthetics matter, but not too much.
# 2 Prefer functions, instead of classes, for modularity, composability and encapsulation.
# 3 Functions should not reference functions or other globals defined later in the script.
# 4 Exploit the standard library to its fullest and automate dependency management.
# 5 Sometimes, its ok to break the rules: take advantage of the language but clean up after.
# 6 In case of doubt, play the game to see what happens. Also, you just lost it.
# 7 There is no seventh.


#@# LOCAL PLATFORM

import os
import sys
import time
import traceback
import typing as t

_PYTHON = sys.executable
_PID = os.getpid()
_DIR = os.path.dirname(os.path.abspath(__file__))

BRANCH = 'main'
RELEASE = '0.1'
DEBUG = True
APP = os.path.basename(_DIR)  # Currently: 'qaczar'
LANG = 'en'

def iso8601() -> str: 
    """Let time flow in a single direction, one second at a time."""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str, div: str = '', trace: bool =False,  _at=None) -> None: 
    """Let the music of the spheres guide your steps."""
    # TODO: Consider a debug only function that also stores the message in a log file.
    global _PID
    frame = _at or sys._getframe(1)  
    if div: print((div or '-') * (100 // len(div)), file=sys.stderr)
    print(f'[{_PID}:{frame.f_lineno} {iso8601()}] {frame.f_code.co_name}:  {msg}', file=sys.stderr)
    if trace: traceback.print_stack(frame, file=sys.stderr)

def halt(msg: str, trace: bool =False) -> t.NoReturn:
    """Let the halting problem be proven empirically."""
    frame = sys._getframe(1)
    emit(f"{msg} <- Final message.", _at=frame)
    emit(f"Halting all processes.", _at=frame)
    if trace: traceback.print_stack(frame, file=sys.stderr)
    sys.exit(0)

def _mtime_file(fname: str) -> float:
    """Let time be an illusion, and mtime doubly so."""
    if not os.path.isfile(fname): return 0.0
    return os.path.getmtime(fname)

def _read_file(fname: str, encoding=None) -> bytes | str:
    """Consult millions of flip-flops on the histories of dead programs."""
    with open(fname, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def _write_file(fname: str, data: bytes | str, encoding=None) -> None:
    """Rearrange millions of flip-flops into an elaborate mausoleum."""
    if encoding and not isinstance(data, str): data = str(data)
    base_dir = os.path.dirname(fname)
    if base_dir and not os.path.isdir(base_dir): os.makedirs(base_dir)
    with open(fname, 'wb' if not encoding else 'w', encoding=encoding) as f: f.write(data)


#@# META-PROGRAMMING

import importlib
import functools

def timed(func: t.Callable) -> t.Callable:
    """Let every function be judged with its proper measure."""
    global DEBUG
    if not DEBUG: return func
    @functools.wraps(func)
    def _timed(*args, **kwargs):
        start = time.time(); elapsed = time.time() - start
        result = func(*args, **kwargs)
        emit(f"Function <{func.__name__}> {args=} {kwargs=} took {elapsed:.4f} seconds.")
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
    """Let every function reach as far as it needs for its dependencies."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            imported = [_pip_import(module) for module in modules]
            return f(*imported, *args, **kwargs)
        return wrapper
    return decorator
    

#@# SUBPROCESSING

import atexit
import subprocess 

def _args_line(*args: tuple[str], **kwargs: dict) -> tuple[str]:
    for k, v in kwargs.items(): 
        args += (f'--{k}=\'{v}\'',) if isinstance(v, str) else (f'--{k}={v}',)
    return args

def _split_args(args: list[str]) -> tuple[tuple, dict]:
    largs, kwargs = [], {}
    for arg in args:
        if '=' in arg: 
            __key, __value = arg[2:].split('=')
            if __value.startswith("'") and __value.endswith("'"): __value = __value[1:-1]
            kwargs[__key] = __value
        else: largs.append(arg)
    return tuple(largs), kwargs

def _setup_py_venv() -> None:
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
    subprocess.run([_PYTHON, '-m', 'pip', 'install', '-r', 'requirements.txt', '--quiet'])

def _start_py(script_path: str, *args: list[str], **kwargs: dict) -> subprocess.Popen:
    global _PYTHON
    line_args = [str(a) for a in _args_line(*args, **kwargs)]
    emit(f"Start python script '{script_path}' {line_args=}.")
    # Popen is a context manager, but we want to keep proc alive and not wait for it.
    # We cannot use run() for this. Remember to manually terminate the process later.
    proc = subprocess.Popen([_PYTHON, script_path, *line_args],
                            stdout=sys.stdout, stderr=sys.stderr)
    proc._args, proc._kwargs = args, kwargs  # Magic for restart_py
    atexit.register(proc.terminate)
    return proc

def _stop_py(proc: subprocess.Popen) -> tuple[tuple, dict]:
    # emit(f"Stopping {proc.pid=}.")
    proc.terminate(); proc.wait()
    atexit.unregister(proc.terminate)
    return proc._args, proc._kwargs

def _restart_py(proc: subprocess.Popen = None) -> subprocess.Popen:
    global APP
    if proc and proc.poll() is None: 
        args, kwargs = _stop_py(proc)
    else: args, kwargs = [], {}
    return _start_py(f'{APP}.py', *args, **kwargs)

def _watch_forever(proc: subprocess.Popen, fname: str) -> t.NoReturn:  
    """Let the script die and restart it. If it dies twice, stop the watcher."""
    source, old_mtime, stable = _read_file(fname), _mtime_file(fname), True
    while True:
        time.sleep(2.6)
        if (new_mtime := _mtime_file(fname)) != old_mtime:
            mutation, old_mtime = _read_file(fname), new_mtime
            if mutation != source:
                emit(f"Mutation detected. Restart and mark unstable.")
                proc, stable = _restart_py(proc), False
            continue
        if proc.poll() is not None:  
            if proc.returncode == 0: sys.exit(0)  # Halt from below.
            if stable:
                emit(f"Script died {proc.returncode=}. Restart and mark unstable.")
                proc, stable = _restart_py(proc), False
                continue
            halt(f"Script died twice. Stopping watcher.")  # Halt from above.
        if not stable:
            emit(f"Stabilizing {proc.pid=}.")
            source, stable = _read_file(fname), True
        

#@# DATABASE

import sqlite3
import threading
import collections

_LOCAL = threading.local()
_SCHEMA = collections.defaultdict(dict)

def _init_table(_db, table: str, cols: list[str]) -> None:
    global _SCHEMA, APP
    # emit(f"Create table: {table} {cols=}")
    sql = (f"CREATE TABLE IF NOT EXISTS {table} ({', '.join(cols)}, " 
            f"ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP, "
            f"id INTEGER PRIMARY KEY AUTOINCREMENT)")
    _SCHEMA[APP][table] = sql
    _db.execute(sql)

def _insert(_db, table: str, *values) -> None:
    sql = (f"INSERT INTO {table} VALUES " 
            f"({', '.join('?' * len(values))}, CURRENT_TIMESTAMP, NULL)")
    try:
        c = _db.execute(sql, values)
        return c.lastrowid
    except Exception as e:
        emit(f"Error on SQL: {sql} with values: {values}")
        e.args = (f"{e.args[0]}: \n{sql}",) + e.args[1:]
        raise e

def _connect_db() -> sqlite3.Connection:
    # TODO: Test this with multiple requests that write to the database.
    global APP, _LOCAL, _PID
    if hasattr(_LOCAL, '{APP}_db'): return getattr(_LOCAL, '{APP}_db')
    _db = sqlite3.connect(f'{APP}.sqlite3')
    _init_table(_db, f'{APP}_instances', ['app_name TEXT', 'pid TEXT'])
    last_pid = _db.execute(
            f"SELECT pid FROM {APP}_instances ORDER BY id DESC LIMIT 1").fetchone()
    if last_pid and last_pid[0] != _PID:
        _insert(_db, f'{APP}_instances', APP, _PID)
        # Run other code that should only run once per app instance here.
        _db.commit()
    setattr(_LOCAL, '{APP}_db', _db)
    return _db
    
def _storage_type(type_: type) -> str | None:
    if type_ in (int, float): return 'REAL'
    elif type_ in (str,): return 'TEXT'
    elif type_ in (bool,): return 'INTEGER'
    else: raise TypeError(f"Unsupported storage type: {type_}")
    
def _func_params_cols(func: t.Callable) -> list[str]:
    columns = []
    for name, param in inspect.signature(func).parameters.items():
        col_type = _storage_type(param.annotation)
        if col_type: columns.append(f'{name} {col_type}')
    return columns

def recorded(func: t.Callable) -> t.Callable:
    """Let all calls to the decorated function be recorded in the database."""
    func_name = func.__name__
    with _connect_db() as db:
        # TODO: Define the columns based on the function signature automatically.
        # TODO: Don't mix this logic with FORMS, recorded can be used for more.
        _init_table(db, f"{func_name}__params", _func_params_cols(func))
        _init_table(db, f"{func_name}__result", 
            ["result TEXT", "seq INTEGER", "params_id INTEGER"])
    @functools.wraps(func)
    def _recorded(*args, **kwargs):
        with _connect_db() as db:
            params_id = _insert(db, f'{func_name}__params', *args, *kwargs.values())
            results = func(*args, **kwargs)
            # emit(f"{func_name}({args=} {kwargs=}) -> {results}")
            if not isinstance(results, (list, tuple)): results = [results]
            for seq, result in enumerate(results):
                _insert(db, f'{func_name}__result', result, seq, params_id)
            db.commit()
        return result
    return _recorded

def _purge_database():
    global APP, _SCHEMA
    with _connect_db() as db:
        for table in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            if table[0] in _SCHEMA[APP]: continue
            if table[0].startswith(f'{APP}_'): continue
            if table[0].startswith(f'sqlite_'): continue
            emit(f"Purge unused table: {table[0]}")
            db.execute(f"DROP TABLE {table[0]}")
        db.commit()


#@# SITE DIRECTORY

import contextlib

@contextlib.contextmanager
def set_site_dir(site: str) -> str:
    """Set the directory where the site is served from."""
    global _LOCAL
    setattr(_LOCAL, 'site', site)
    yield os.path.join(os.getcwd(), site)
    delattr(_LOCAL, 'site')

def read_file(fname: str, encoding=None) -> str | bytes:
    """Let each site read files from their own directory."""
    global _LOCAL
    site_fname = os.path.join(_LOCAL.site, fname)
    return _read_file(site_fname, encoding)

def write_file(fname: str, data: bytes | str, encoding=None) -> None:
    """Let each site write files to their own directory."""
    global _LOCAL
    site_fname = os.path.join(_LOCAL.site, fname)
    _write_file(site_fname, data, encoding)


#@# HTML GENERATION

import inspect
import itertools

@functools.lru_cache(maxsize=128)
def elem(tag: str, content: str=None, cdata: bool=False, **attrs) -> str:
    """Let all serialization happen through hypertext."""
    if 'data' in attrs: 
        for k, v in attrs['data'].items(): attrs[f'data-{k}'] = v
        del attrs['data']
    attrs = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
    if not isinstance(content, str): content = ''.join(content)
    if attrs and not content: return f'<{tag} {attrs}/>'
    if not content: return f'<{tag}/>'
    if cdata: content = f'<![CDATA[{content}]]>'
    return f'<{tag} {attrs}>{content}</{tag}>'

@functools.lru_cache(maxsize=128)
def input_elem(field: str, param: inspect.Parameter) -> str:
    """Let function annotations determine input types and validations."""
    input_type = 'text'
    if param.annotation is not param.empty:
        if param.annotation is int: input_type = 'number'
        elif param.annotation is bool: input_type = 'checkbox'
    attrs = {'name': field, 'type': input_type, 'title': field}
    if param.default is not param.empty:
        attrs['value'] = param.default
        if param.annotation is bool: attrs['checked'] = 'checked'
    return elem('input', **attrs)

@functools.lru_cache(maxsize=128)
def form_elem(func: t.Callable) -> str:
    """Let function signatures determine form fields."""
    func_name = func.__name__
    form = f"<form action='{func_name}' method='POST'>" 
    for name, param in inspect.signature(func).parameters.items():
        if not param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD): continue
        if name.startswith('_'): continue
        if param.annotation is param.empty: continue
        form += f"<label for='{name}'>{name.upper()}:</label>"
        form += input_elem(name, param) + "<br>"
    form += f"<button type='submit'>EXECUTE</button></form>"
    return form

def html_elem(body: str) -> str:
    """Let there be some standard boilerplate HTML."""
    global APP, _LOCAL
    if hasattr(_LOCAL, 'site'):
        site_css = os.path.join(_LOCAL.site, f'{_LOCAL.site}.css')
        if os.path.exists(site_css): style = _read_file(site_css, encoding='utf-8')
    else: style = _read_file(f'{APP}.css', encoding='utf-8')
    title = f"{APP} - {_LOCAL.site}" if hasattr(_LOCAL, 'site') else APP
    return f"""
    <!DOCTYPE html><html lang="en">
    <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <style>{style}</style><title>{title}</title>
    </head>
    <body>{body}</body>
    </html>
    """

def hyper(tag: str, wrap: str | tuple = None, css: str = None, **attrs) -> t.Callable:
    """Let the decorated function output hypertext automatically."""
    if css: attrs['class'] = css
    def _decorator(func: t.Callable, _tag=tag, _wrap=wrap, _attrs=attrs) -> t.Callable:
        @functools.wraps(func)
        def _hyper(*args, **kwargs):
            result = func(*args, **kwargs)
            if isinstance(_wrap, str):
                if isinstance(result, str): result = elem(_wrap, result)
                else: result = ''.join(elem(_wrap, r) for r in result) 
            elif isinstance(_wrap, tuple):
                result = ''.join(elem(w, r) 
                    for w, r in itertools.zip_longest(_wrap, result, fillvalue=_wrap[-1]))
            if _tag in ('html', 'body'): return html_elem(result)
            return elem(_tag, result, **_attrs)
        return _hyper
    return _decorator

def build_html_chain(*func_names: str, **context) -> str:
    """Let all HTML content be generated from pure functions and request context."""
    global _LOCAL
    try:
        if _LOCAL.site not in sys.path: sys.path.append(_LOCAL.site)
        site_module = importlib.import_module(_LOCAL.site)
        funcs = [getattr(site_module, name) for name in func_names]
    except (ModuleNotFoundError, AttributeError):
        try:
            funcs = [globals()[name] for name in func_names]
        except (KeyError, TypeError) as e:
            # TODO: Replace with calling a function that generates the error page.
            return f"<h1>ERROR: {e}</h1>"
    for i, func in enumerate(reversed(funcs)): 
        emit(f"Step #{i} {func.__name__}({context})")
        block = func(**context)
        context[func.__name__] = block
    return block


#@# WEB COMPONENTS

@hyper('header', ('h1', 'nav'))
def header_nav(**context) -> str:
    """Let this be the header of the page."""
    return [
            elem('a', 'QACZAR', href='/'),
            elem('a', 'ABOUT', href='/about'),
            elem('a', 'CONTACT', href='/contact'),
        ]

@hyper('article', css='roadmap')
def roadmap(**context) -> str:
    """Let this be the roadmap of the page."""
    return [
            elem('h2', 'ROADMAP'),
            elem('p', 'This is the roadmap of the page.'),
        ]



@hyper('body', ('header', 'main', 'footer'))
def hello_world(**context) -> str:
    """Let this be the default page. It shall have a roadmap.""" 	
    # TODO: Add all the missing elements (such as the roadmap) to the welcome page.
    return [
            header_nav(**context),
            elem('p', f"Here's a roadmap of what's coming up next."),
        ]


#@# HTTPS SERVER

import ssl
import importlib
import datetime as dt
import http.server as hs
import socketserver as ss
import urllib.parse as parse

SITE = 'qaczar.com'
HOST, PORT = 'localhost', 9443

@imports('cryptography.x509',
    'cryptography.hazmat.primitives.asymmetric.rsa',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.primitives.serialization')
def _build_ssl_certs(x509, rsa, hashes, ser) -> tuple[str, str]:
    # TODO: Each tenant should have their own SSL certificates.
    global HOST
    if not os.path.exists('.ssl'): os.mkdir('.ssl')
    certname, keyname = '.ssl/cert.pem', '.ssl/key.pem'
    if os.path.exists(certname) and os.path.exists(keyname):
        cert = x509.load_pem_x509_certificate(_read_file(certname))
        if cert.not_valid_after > dt.datetime.utcnow(): return certname, keyname
        else: os.remove(certname); os.remove(keyname)
    emit(f"Generating new self-signed SSL certificates for {HOST=}.")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    _write_file(keyname, key.private_bytes(
            encoding=ser.Encoding.PEM,
            format=ser.PrivateFormat.PKCS8,
            encryption_algorithm=ser.NoEncryption()))
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, HOST)])
    cert = x509.CertificateBuilder() \
            .subject_name(name) \
            .issuer_name(name) \
            .public_key(key.public_key()) \
            .serial_number(x509.random_serial_number()) \
            .not_valid_before(dt.datetime.utcnow()) \
            .not_valid_after(dt.datetime.utcnow() + dt.timedelta(days=3)) \
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]), critical=False) \
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True) \
            .sign(key, hashes.SHA256())
    _write_file(certname, cert.public_bytes(ser.Encoding.PEM))
    return certname, keyname

@recorded
def access_log(address: str, message: str) -> None:
    """Let the access log be recorded in the database for analysis."""
    # TODO: Add more parameters to the access log.
    emit(f"Access from {address} {message}")

class RequestHandler(hs.SimpleHTTPRequestHandler):
    # TODO: Performance testing is needed to ensure this approach will work in the long run.

    def log_message(self, format, *args):
        """Let us not put @recorded on this directly, it messes with *args."""
        access_log(self.address_string(), format % args)

    def _rfile_read(self, size: int = None) -> bytes:
        """Let us read the request body (ie. for parsing form data)."""
        if size is None: size = int(self.headers['Content-Length'])
        return self.rfile.read(size)

    def _build_response(self, method: str = None) -> bool:
        global SITE
        """Let each request be parsed and processed. If needed, overwrite the response file."""
        # I really hope I don't have to rewrite this one function forever. --Sysyphus
        self.work_path, self.start = None, time.time()
        if self.path == '/' or not self.path: self.path = f'/{SITE}/hello_world.html'
        if self.path.endswith('/'): self.path += 'index.html'
        if method != 'POST': data = {}
        else: data = parse.parse_qs(self._rfile_read().decode('utf-8'))
        pure_path, qs = self.path.split('?', 1) if '?' in self.path else (self.path, '')
        if '.' not in pure_path: pure_path += '.html'
        if pure_path.endswith('.html'):  # Everything else is served as-is.
            qs = parse.parse_qs(qs) if qs else {}
            site, *funcs = [func for func in pure_path[1:-5].split('/') if func]
            if not funcs: site, funcs = SITE, [site]
            with set_site_dir(site):
                emit(f"Building {site=} {funcs=} {qs=} {data=}")
                content = build_html_chain(*funcs, **qs, **data)
            self.work_path = os.path.join('.server', self.path[1:])
            _write_file(self.work_path, content, encoding='utf-8')
        
    def translate_path(self, path: str = None) -> str:
        """Let each request be served from its work path (.server) when needed."""
        return super().translate_path(path) if not self.work_path else self.work_path

    def do_HEAD(self) -> None:
        self._build_response('HEAD'); return super().do_HEAD()
        
    def do_GET(self) -> None:
        self._build_response('GET'); return super().do_GET()
    
    def do_POST(self) -> None:
        self._build_response('POST'); return super().do_GET()
    
    def end_headers(self) -> None:
        """Let us add some headers to the end of the response (before the body)."""
        duration = time.time() - self.start
        self.send_header('Server-Timing', f'miss;dur={duration:.4f}')
        if not self.work_path:
            self.send_header('Cache-Control', f'Etag: {_mtime_file(self.path)}')
        return super().end_headers()
    
    def send_header(self, keyword: str, value: str) -> None:
        """Let us override some headers before they are sent."""
        global RELEASE
        if keyword.lower() == 'content-type' and 'text' in value and 'encoding' not in value:
            value = f"{value}; charset=utf-8"
        elif keyword == 'Server': value = f"{value} qaczar.py/{RELEASE}"
        emit(f"HTTP header {keyword}: {value}")
        return super().send_header(keyword, value)

class SSLServer(ss.ThreadingTCPServer):
    """Let us subclass the ThreadingTCPServer to add SSL support."""
    # TODO: This creates 1 thread per request, which is not ideal. Implement a thread pool.
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        ss.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(*_build_ssl_certs())
        self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True) 


#@#  SELF TESTING

_COUNTER = 0

@imports('urllib3')
def request_factory(urllib3):
    """Let us make requests to the server and check the response."""	
    # TODO: Design a string for the user-agent and use it to track tests.
    global HOST, PORT, APP
    http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=_build_ssl_certs()[0])
    def _request(fname:str, data:dict = None, status:int = 200):
        global _COUNTER
        fname = f"{APP}/{fname}"
        url = f"https://{HOST}:{PORT}/{fname}"
        r = http.request('POST' if data else 'GET', url, fields=data, timeout=30)
        assert r.status == status, f"Request to {url} failed with status {r.status}"
        # emit(f"Request {_COUNTER} to {url} succeeded with status {r.status}")
        _COUNTER += 1
        return r.data.decode('utf-8')
    return _request
    
def test_server(*args, **kwargs) -> t.NoReturn:
    """Let us test the server by making http requests to it."""
    # TODO: Test other special paths such as blank, /, etc.
    # TODO: Test submitting a form (ie. sign_guestbook).
    global APP
    request = request_factory()
    assert 'qaczar' in request(f'/hello_world.html')


#@#  REPOSITORY

def _commit_source() -> t.NoReturn:
    """Let us commit the source code to the git repository."""
    # TODO: Create missing branch if not exists when pushing to git.
    global BRANCH
    os.system('git add .')
    os.system('git commit -m "auto commit" -q')
    os.system(f'git push origin {BRANCH} -q')
    emit(f"Source committed to {BRANCH}.")


#@# BASE ROLES

def watcher_role(*args, **kwargs) -> t.NoReturn:
    """Let us watch ourselves to see we may never halt until commanded."""	
    global APP
    _setup_py_venv()
    kwargs['watcher'] = os.getpid()
    _watch_forever(_start_py(f'{APP}.py', *args, **kwargs), f'{APP}.py')

def server_role(*args, **kwargs) -> t.NoReturn:
    """Let us generate, serve and store the site content and user input."""	
    # TODO: Catch port being in use and suggest a different port.
    global APP, HOST, PORT
    _purge_database()
    with SSLServer((HOST, int(PORT)), RequestHandler) as httpd:
        atexit.register(httpd.shutdown)
        kwargs['server'] = f'{HOST}:{PORT}'
        _start_py(f'{APP}.py', *args, **kwargs)
        emit(f"Server ready at https://{HOST}:{PORT}")
        httpd.serve_forever()

def tester_role(*args, **kwargs) -> t.NoReturn:
    """Let us test the server by making http requests to it."""
    # TODO: Add automatic tests to prevent public API regressions.
    # TODO: Keep the tester running and re-run tests when source changes.
    # TODO: Have a keep-alive ping to detect when the server is down.
    for passed, test in enumerate(globals().keys()):
        if test.startswith(f'test_'): 
            globals()[test](*args, **kwargs)
    else:
        emit(f"Tests passed: {passed}.")
        _commit_source()

def worker_role(*args, **kwargs) -> t.NoReturn:
    """Let us do work that is not related to the serving requests."""
    raise NotImplementedError("Worker role not implemented.")


#@# ROLE SELECTOR

def _role_dispatch(*args, **kwargs) -> t.NoReturn:
    """Let each instance decide their own role, based on what's missing."""
    if 'watcher' not in kwargs: role = watcher_role
    elif 'server' not in kwargs: role = server_role
    elif 'tester' not in kwargs: role = tester_role
    else: role = worker_role
    role_name = role.__name__.replace('_role', '')
    try:
        emit(f"Started '{role_name}' {args=} {kwargs=}.")
        role(*args, **kwargs)
    except AssertionError as e:
        (halt if DEBUG else emit)(f"Assertion failed: {e}")
    except KeyboardInterrupt:
        halt("Interrupted by user.")

if __name__ == "__main__":
    if len(sys.argv) > 1: _ARGS, _KWARGS = _split_args(sys.argv[1:])
    else: _ARGS, _KWARGS = (), {}
    _role_dispatch(*_ARGS, **_KWARGS)
    