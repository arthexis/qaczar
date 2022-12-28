#!/usr/bin/env python
# -*- coding: utf-8 -*-

# qaczar.py: A web authoring system written in honor of the Self-Inventing.
# by R. J. Guillén-Osorio (rjgo [at] qaczar [dot] com) 2022-2023.

# Anyone can create their own web presence by running this script on their own computer. Try it!

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

BRANCH = 'main'
RELEASE = '0.1'
LANG = 'en'
DEBUG = True
PYTHON = sys.executable
PID = os.getpid()
DIR = os.path.dirname(os.path.abspath(__file__))
APP = os.path.basename(DIR)  # Currently: 'qaczar'


def iso8601() -> str: 
    """Let time flow in a single direction, one second at a time."""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str, div: str = '', trace: bool =False,  _at=None) -> None: 
    """Let the music of the spheres guide your steps."""
    global PID
    fr = _at or sys._getframe(1)  
    if div: print((div or '-') * (100 // len(div)), file=sys.stderr)
    print(f'[{PID}:{fr.f_lineno} {iso8601()}] {fr.f_code.co_name}:  {msg}', file=sys.stderr)
    if trace: traceback.print_stack(fr, file=sys.stderr)

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

def _pip_import(module: str) -> t.Any:
    name = module.split('.')[0]
    requirements = _read_file('requirements.txt', encoding='utf-8').splitlines()
    if name not in requirements:    
        subprocess.run([sys.executable, '-m', 'pip', 'install', name, '--quiet'])
        with open('requirements.txt', 'a', encoding='utf-8') as f: f.write(f'{name}\n')
    return importlib.import_module(module)

def timed(func: t.Callable) -> t.Callable:
    """Let every function be judged with its proper measure."""
    global DEBUG
    if not DEBUG: return func
    @functools.wraps(func)
    def _timed(*args, **kwargs):
        start = time.time(); elapsed = time.time() - start
        result = func(*args, **kwargs)
        ln = sys._getframe(1).f_lineno
        emit(f"Func <{func.__name__}> ({ln}) {args=} {kwargs=} took {elapsed:.4f} secs.")
        return result
    return _timed

def imports(*modules: tuple[str]) -> t.Callable:
    """Let every function reach as far as it needs for its dependencies."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            imported = [_pip_import(module) for module in modules]
            return f(*imported, *args, **kwargs)
        return wrapper
    return decorator

SCHEDULE = {}

def scheduled(interval: int = 60, once: bool = False) -> t.Callable:
    """Let us schedule functions to be run periodically by a worker."""
    assert interval > 0
    global SCHEDULE
    def _scheduled(f):
        SCHEDULE[f.__name__] = time.time() + interval
        f.__interval__ = interval
        @functools.wraps(f)
        def __scheduled(*args, **kwargs):
            result = f(*args, **kwargs)
            if not once: SCHEDULE[f.__name__] = time.time() + interval
            return result
        return __scheduled
    return _scheduled

def _safe_globals() -> list[str]:
    return {k: v for k, v in globals().items() 
        if not k.startswith('_') and k not in sys.modules}

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
    global PYTHON
    if not os.path.isfile('requirements.txt'): 
        _write_file('requirements.txt', '', encoding='utf-8')
    if sys.platform.startswith('win'):
        if not os.path.isfile('.venv/Scripts/python.exe'): 
            subprocess.run([sys.executable, '-m', 'venv', '.venv'])
        PYTHON = '.venv/Scripts/python.exe'
    elif not os.path.isfile('.venv/bin/python3'): 
        subprocess.run([sys.executable, '-m', 'venv', '.venv'])
        PYTHON = '.venv/bin/python3'
    subprocess.run([PYTHON, '-m', 'pip', 'install', '--upgrade', 'pip', '--quiet'])
    subprocess.run([PYTHON, '-m', 'pip', 'install', '-r', 'requirements.txt', '--quiet'])

def _start_py(script_path: str, *args: list[str], **kwargs: dict) -> subprocess.Popen:
    global PYTHON
    line_args = [str(a) for a in _args_line(*args, **kwargs)]
    emit(f"Spawn '{script_path}' {line_args=}.")
    # Popen is a context manager, but we want to keep proc alive and not wait for it.
    # We cannot use run() for this. Remember to manually terminate the process later.
    proc = subprocess.Popen([PYTHON, script_path, *line_args],
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
            if proc.returncode == 0: sys.exit(0)  # As below so above.
            if stable:
                emit(f"Script died {proc.returncode=}. Restart and mark unstable.")
                proc, stable = _restart_py(proc), False
                continue
            halt(f"Script died twice. Stopping watcher.")  # As above so below.
        if not stable:
            emit(f"Stabilizing {proc.pid=}.")
            source, stable = _read_file(fname), True
        

#@#  REPOSITORY

def commit_hash() -> str:
    """Let us get the hash of the last commit."""
    try: return os.popen('git rev-parse HEAD').read().strip()[0:8]
    except: return '00000000'

COMMIT = commit_hash()

def _commit_source() -> str:
    """Let us commit the source code to the git repository."""
    # TODO: Create missing branch if not exists when pushing to git.
    global BRANCH
    os.system('git add .')
    os.system('git commit -m "auto commit" -q')
    os.system(f'git push origin {BRANCH} -q')
    return commit_hash()


#@# SITE DIRECTORY

import tomllib
import collections

_CACHE = collections.defaultdict(dict)

def site_context(site: str = None, context: dict = None) -> str:
    """Let us keep a running context for every request to a site."""
    global _LOCAL, _CACHE
    if site: 
        context['site'] = site
        context['work_path'] = wp = os.path.join(os.getcwd(), site)
        site_fname = os.path.join(wp, 'site.toml')
        site_mtime = _mtime_file(site_fname)
        if site not in _CACHE or _CACHE[site][site_fname] != site_mtime:
            with open(site_fname, 'rb') as f:
                emit(f"Loading site config {site_fname=}.")
                _CACHE[site] = {site_fname: site_mtime, **tomllib.load(f)}
        context.update(_CACHE[site])
        setattr(_LOCAL, 'context', context)
    return _LOCAL.context

def read_file(fname: str, encoding=None) -> str | bytes:
    """Let each site read files from their own directory first, and the base second."""
    context = site_context()
    site_fname = os.path.join(context['work_path'], fname)
    if not site_fname or not os.path.exists(site_fname):
        site_fname = os.path.join(os.getcwd(), fname)
    return _read_file(site_fname, encoding)

def write_file(fname: str, data: bytes | str, encoding=None) -> None:
    """Let each site write files to their own directory (never to the base)."""
    context = site_context()
    site_fname = os.path.join(context['work_path'], fname)
    _write_file(site_fname, data, encoding)


#@# DATABASE

import sqlite3
import threading

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
    global APP, _LOCAL, PID
    if hasattr(_LOCAL, '{APP}_db'): return getattr(_LOCAL, '{APP}_db')
    _db = sqlite3.connect(f'{APP}.sqlite3')
    _init_table(_db, f'{APP}_instances', ['app_name TEXT', 'pid TEXT'])
    last_pid = _db.execute(
            f"SELECT pid FROM {APP}_instances ORDER BY id DESC LIMIT 1").fetchone()
    if last_pid and last_pid[0] != PID:
        _insert(_db, f'{APP}_instances', APP, PID)
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
        if param.annotation == inspect._empty: continue
        col_type = _storage_type(param.annotation)
        if col_type: columns.append(f'{name} {col_type}')
    if not columns: 
        raise TypeError(f"Function {func.__name__} has no supported parameters.")
    return columns

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


#@# HTML ELEMENTS

import html
import pprint
import inspect

def elem(tag: str, *contents, data: dict=None, cls: str = None, **attrs) -> str:
    """Let all serialization happen through hypertext, as originally intended."""
    if cls and cls.strip(): attrs['class'] = cls
    if data: 
        for k, v in data.items(): attrs[f'data-{k}'] = v
    attrs = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
    # TODO: There has to be an error, contents is a list of strings, not a string.
    if isinstance(contents, str): contents = [contents]
    contents = ''.join(str(c) for c in contents)
    if attrs and not contents: return f'<{tag} {attrs}/>'
    if not contents: return f'<{tag}/>'
    return f'<{tag} {attrs}>{contents}</{tag}>'

elem_h1 = functools.partial(elem, 'h1')
elem_h2 = functools.partial(elem, 'h2')
elem_h3 = functools.partial(elem, 'h3')
elem_h4 = functools.partial(elem, 'h4')
elem_p = functools.partial(elem, 'p')

def elem_button(*contents, **attrs) -> str:
    return elem('button', *contents, **attrs)

def elem_list(*items, tag: str='ul', attr_func: t.Callable = None) -> str:
    if len(items) == 1 and not isinstance(items[0], str): items = items[0]
    if attr_func: content = ''.join(elem('li', item, **attr_func(item)) for item in items)
    else: content = ''.join(elem('li', item) for item in items)
    return elem(tag, content) if tag else content

def elem_section(title: str = None, *content, **attrs) -> str:
    # Sections are full width, so they can contain a title.
    if title: content = elem_h2(title), *content
    return elem('section', *content, **attrs)

def elem_pre(*content, **attrs) -> str:
    if content and isinstance(content[0], dict):
        # TODO: Pprint is fine for debugging, but it's not very readable.
        content = (pprint.pformat(content[0]), *content[1:])
    content = (html.escape(str(c)) for c in content)
    return elem('pre', *content, **attrs)

def elem_article(tag: str = 'article', *content, **attrs) -> str:
    return elem(tag, *content, cls='card', **attrs)

def elem_label(css: str = '', *content, **attrs) -> str:
    return elem('span', *content, cls=f'label {css}', **attrs)

def elem_grid(*content, **attrs) -> str:
    # TODO: Automatically generate the grid CSS code.
    return elem('div', *content, cls='grid', **attrs)

# https://htmx.org/docs/#introduction
HTMX_SRC = 'https://unpkg.com/htmx.org@1.8.4'

def elem_html_body(*sections, **attrs) -> str:
    """Let there be some standard boilerplate HTML."""
    # TODO: Generate the CSS code dynamically instead of reading a file.
    global HTMX_SRC, LANG
    context = site_context()
    site = context.get('site')
    title = context.get('title') or site
    body = elem('body', *sections, **attrs)
    # Don't break this boilerplate into smaller functions unless needed.
    return f"""
    <!DOCTYPE html><html lang="{LANG}"><head>
    <title>{title}</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <meta name="htmx-config" content='{{"defaultSwapStyle":"outerHTML"}}'>
    <script src="{HTMX_SRC}"></script>
    <link rel="stylesheet" href="/{site}/style.css" type="text/css" />
    </head>{body}</html>
    """


#@# HTML GENERATOR

# TODO: Consider tracking components with the database instead of a global.
_INDEX = collections.defaultdict(dict)

def hyper(
        tag: str, method: str = 'get', trigger: str = None, target: str = None, 
        history: bool = None, **attrs) -> t.Callable:
    """Let us decorate a function to output hypertext."""
    global _INDEX, DEBUG
    if trigger: attrs['hx-trigger'] = trigger
    if target: attrs['hx-target'] = target
    if history or (tag == 'body' and history is not False): attrs['hx-push-url'] = 'true'
    def _hyper(
            func: t.Callable, _tag=tag, _method=method, _attrs=attrs) -> t.Callable:
        _attrs[f'hx-{_method}'] = func.__name__
        if DEBUG: _attrs['data-ln'] = func.__code__.co_firstlineno
        _INDEX[_tag][func.__name__] = func
        @functools.wraps(func)
        def __hyper(*args, **kwargs):
            try:
                result = func(*args, **kwargs) or ()
                if not result: emit(f"{func.__name__}({args=} {kwargs=}) -> Empty result.")
            except TypeError as e:
                emit(f"Error: {e} {func.__name__}({args=} {kwargs=})"); raise e
            if _tag == 'body': return elem_html_body(*result, **_attrs)
            return elem(_tag, *result, **_attrs)
        return __hyper
    return _hyper


#@# SITE COMPONENTS
# The objective is to have a single set of functions to generate all possible websites.

@hyper('nav')
def site_nav() -> str:
    global _INDEX
    context = site_context()
    site = context.get('site')
    body_links = [elem('a', func_name, href=f'/{site}/{func_name}.html') 
        for func_name in _INDEX['body'].keys() if func_name != 'index']
    span = elem('span', context.get('site').upper())
    brand = elem('a', span, href=f'/{site}/index.html', cls='brand')
    return brand, *body_links

@hyper('section')
def site_index() -> str:
    global _INDEX
    context = site_context()
    site = context['site']
    about = context.get('about')
    links = [elem('a', elem_p(name), href=f'/{site}/{name}.html') 
        for name in _INDEX['section'].keys()]
    return elem_h1(about.get('title')), *links

@hyper('section')
def site_articles(*articles) -> str:
    # TODO: Find why the line number is not being added to the section html.
    # TODO: Context also doesn't contain the data from site.toml
    context = site_context()
    return elem_h1('Articles'), *articles

@hyper('footer')
def site_footer() -> str:
    context = site_context()
    links = [elem('a', f' [{name}] ', href=href, target='_blank') 
        for name, href in context['links'].items()]
    return elem('a', f'Powered by qaczar.py [source]', href=f'/qaczar.py'), *links


#@# SITE PAGES

@hyper('body')  # Default page.
def index() -> str:
    """Let this be the default page (showcase functionality).""" 
    return elem('main', site_nav(), site_index(), site_articles(), site_footer())

@hyper('body')  
def debugger() -> str:
    """Let this page be used for experimentation.""" 
    context = site_context()
    reports = [elem_section('Context', elem_pre(context))]
    reports.append(elem_section('Globals', elem_pre(_safe_globals())))
    # Remove the footer in case it messes up the debugger output, but keep the nav.
    return elem('main', site_nav(), *reports)

# Blog where articles are executable python code.


#@# HTTPS SERVER

import ssl
import secrets
import importlib
import datetime as dt
import http.server as hs
import socketserver as ss
import urllib.parse as parse

MAIN_SITE = 'qaczar.com'
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
    if address != '127.0.0.1':	
        emit(f"Access logged from {address} {message}")

SESSIONS = collections.defaultdict(dict)

class ComplexHTTPRequestHandler(hs.SimpleHTTPRequestHandler):
    # TODO: Performance testing is needed to ensure this approach will work in the long run.

    def log_message(self, format, *args):
        """Let us not put @recorded on this directly, it messes with *args."""
        access_log(self.address_string(), format % args)

    def _rfile_read(self, size: int = None) -> bytes:
        """Let us read the request body (ie. for parsing form data)."""
        if size is None: size = int(self.headers['Content-Length'])
        return self.rfile.read(size)

    def _send_redirect(self, path: str):
        self.send_response(301)
        self.send_header('Location', path)

    # Check if the Session-ID is valid, and if not, create a new one.
    def _check_session(self) -> bool:
        global SESSIONS
        agent, address = self.headers['User-Agent'], self.address_string()
        if address not in SESSIONS or agent not in SESSIONS[address]: 
            self.session_id = sid = secrets.token_urlsafe(32)
            SESSIONS[address][agent] = sid
            emit(f"Session {sid[0:8]=} created for {address=} {agent=}.")
        else: self.session_id = SESSIONS[address][agent]
        return True
    
    def _request_context(self, **kwargs) -> dict:
        return {
                'session_id': self.session_id, 
                'address': self.address_string(), 
                'path': self.path, 
                'headers': dict(self.headers.items()),  
                'method': self.command,
                **kwargs
            }

    def _build_response(self, method: str = None) -> None:
        global MAIN_SITE
        """Let each request be parsed and processed. If needed, overwrite the response file."""
        # I hope I don't have to rewrite this one function forever. --Sysyphus
        self.work_path, self.start = None, time.time()
        if not self._check_session(): 
            self.send_response(401); return
        if self.path == '/' or not self.path: 
            self._send_redirect(f'/{MAIN_SITE}/index.html'); return
        if method != 'POST': data = {}
        else: data = parse.parse_qs(self._rfile_read().decode('utf-8'))
        pure_path, qs = self.path.split('?', 1) if '?' in self.path else (self.path, '')
        if '.' not in pure_path: 
            self._send_redirect(f'{pure_path}.html' + ('?' + qs if qs else '')); return
        elif pure_path.endswith('.html'):  
            qs = parse.parse_qs(qs) if qs else {}
            site, *folders, func_name = [func for func in pure_path[1:-5].split('/') if func]
            for key, value in self.headers.items():
                if key.startswith('HX-'): qs[key[3:].lower().replace('-', '_')] = value
            site = site + '/' + '/'.join(folders) if folders else site
            site_context(site, self._request_context(**qs, **data))
            content = _safe_globals()[func_name]()
            self.work_path = os.path.join('.server', pure_path[1:])
            _write_file(self.work_path, content, encoding='utf-8')
        # Everything else is served as-is by SimpleHTTPRequestHandler.
        
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
        self.send_header('Server-Timing', f'miss;dur={duration:.6f}')
        self.send_header('Session-ID', self.session_id)
        return super().end_headers()
    
    def send_header(self, keyword: str, value: str) -> None:
        """Let us override some headers before they are sent."""
        global RELEASE
        if keyword.lower() == 'content-type' and 'text' in value and 'encoding' not in value:
            value = f"{value}; charset=utf-8"
        elif keyword == 'Server': value = f"{value} qaczar.py/{RELEASE}"
        # emit(f"HTTP header {keyword}: {value}")
        return super().send_header(keyword, value)

class ThreadingSSLServer(ss.ThreadingTCPServer):
    """Let us subclass the ThreadingTCPServer to add SSL support."""
    # TODO: This creates 1 thread per request, which is not ideal. Implement a thread pool.
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        ss.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
        ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_ctx.load_cert_chain(*_build_ssl_certs())
        self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True) 


#@#  CHAOS TESTING

import random

@imports('urllib3')
def request_factory(urllib3):
    """Let us make requests to the server and check the responses are valid."""	
    http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=_build_ssl_certs()[0])
    session_id = None
    def _request(path: str, data: dict = None):
        global HOST, PORT, PID
        nonlocal session_id
        if path.startswith('/'): path = path[1:]
        url = f"https://{HOST}:{PORT}/{path}"
        method = 'POST' if data else 'GET'
        r = http.request(method, url, fields=data, timeout=1)
        assert r.status == 200, f"Request {method} {url} failed with status {r.status}"
        if not session_id: session_id = r.headers['Session-ID']
        elif session_id != r.headers['Session-ID']:
            emit(f"Session ID changed, possible server restart. Terminate {PID=}")
            sys.exit(1)  
        return r.data.decode('utf-8')
    return _request
    
def _keep_alive(*args, **kwargs) -> t.NoReturn:
    """Let us keep the server active by making periodic requests to it."""
    global MAIN_SITE
    request = request_factory()
    while True: 
        time.sleep(wait := 300)  # Every 5 minutes.
        request(url := f'/{MAIN_SITE}/index.html')
        emit(f"Keep-alive ({wait}s) to {url}")

def test_server_load(*args, **kwargs) -> t.NoReturn:
    """Let us test the server by making http requests to it."""
    global MAIN_SITE
    request = request_factory()
    start = time.time()
    for _ in range(runs := 20): request(f'/{MAIN_SITE}/index.html')
    dur = time.time() - start
    emit(f"Avg. RT: {dur/runs:.6f} secs ({runs/dur:.2f} reqs/sec).")


#@# SCHEDULED TASKS

@scheduled(600)
def _backup_database() -> None:
    """Let us backup the database to the git repository."""
    emit(f"Database backup (faked).")


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
    with ThreadingSSLServer((HOST, int(PORT)), ComplexHTTPRequestHandler) as httpd:
        atexit.register(httpd.shutdown)
        kwargs['server'] = f'{HOST}:{PORT}'
        _start_py(f'{APP}.py', *args, **kwargs)
        emit(f"Ready at https://{HOST}:{PORT}")
        httpd.serve_forever()

def tester_role(*args, **kwargs) -> None:
    """Let us test the server by making http requests to it."""
    passed = 0
    try:
        for gkey in globals().keys():
            if gkey.startswith(f'test_'): 
                globals()[gkey](*args, **kwargs)
                passed += 1
    except Exception as e: 
        emit(f"Tests failed: {e}"); return
    kwargs['tester'] = commit_hash = _commit_source() 
    emit(f"Tests passed: {passed} -> Committed: {commit_hash}")
    _start_py(f'{APP}.py', *args, **kwargs)
    _keep_alive()

def worker_role(*args, **kwargs) -> None:
    """Let us perform scheduled work in the background."""
    # TODO: A scheduled task should update the schedule from the server.
    global SCHEDULE
    if not SCHEDULE: 
        emit("No scheduled tasks."); return
    while True:
        for func_name, next_run in SCHEDULE.items():
            if time.time() >= next_run:
                func = globals()[func_name]; func()
                SCHEDULE[func_name] = next_run + func.__interval__
        time.sleep(1)


#@# ROLE SELECTOR

def _role_dispatch(*args, **kwargs) -> t.NoReturn:
    """Let each instance decide their own role, based on what's missing."""
    if 'watcher' not in kwargs: role_func = watcher_role
    elif 'server' not in kwargs: role_func = server_role
    elif 'tester' not in kwargs: role_func = tester_role
    else: role_func = worker_role  # A cluster can have multiple workers.
    role_name = role_func.__name__.replace('_role', '')
    try:
        emit(f"Started '{role_name}' {args=} {kwargs=}.")
        role_func(*args, **kwargs)
    except AssertionError as e:
        halt(f"Assertion failed {e}", trace=True)
    except KeyboardInterrupt:
        halt("Interrupted by user.")

if __name__ == "__main__":
    if len(sys.argv) > 1: _ARGS, _KWARGS = _split_args(sys.argv[1:])
    else: _ARGS, _KWARGS = (), {}
    _role_dispatch(*_ARGS, **_KWARGS)

__all__ = _safe_globals()
