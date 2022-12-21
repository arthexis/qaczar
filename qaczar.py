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

# <!--


#@# LOCAL PLATFORM

import os
import sys
import time
import traceback
import typing as t

_PYTHON = sys.executable
_PID = os.getpid()
_BRANCH = 'main'
_DIR = os.path.dirname(os.path.abspath(__file__))

DEBUG = False
APP = os.path.basename(_DIR)

def iso8601() -> str: 
    """Returns the current time in ISO 8601 format."""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str, div: str = '', trace: bool =False,  _at=None) -> None: 
    """Prints a message to stderr, enriched with time, PID and line number."""
    global _PID
    frame = _at or sys._getframe(1)  
    if div: print((div or '-') * 100, file=sys.stderr)
    print(f'[{_PID}:{frame.f_lineno} {iso8601()}] {frame.f_code.co_name}:  {msg}', file=sys.stderr)
    if trace: traceback.print_stack(frame, file=sys.stderr)

def halt(msg: str) -> t.NoReturn:
    """Stops the program and all its subprocesses, printing a final message."""
    frame = sys._getframe(1)
    emit(f"{msg} <- Final message.", _at=frame)
    emit(f"Halting all processes.", _at=frame)
    sys.exit(0)

def _mtime_file(fname: str) -> float:
    if not os.path.isfile(fname): return 0.0
    return os.path.getmtime(fname)

_MTIME = _mtime_file(__file__)

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
    """Removes the extraneous indentation from a multi-line string."""	
    indent = len(code) - len(code.lstrip()) - 1
    return '\n'.join(line[indent:] for line in code.splitlines())

def timed(f: t.Callable) -> t.Callable:
    """Decorator to time a function, emitting a message to stderr."""
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
    requirements = _read_file('requirements.txt', encoding='utf-8').splitlines()
    if name not in requirements:    
        subprocess.run([sys.executable, '-m', 'pip', 'install', name, '--quiet'])
        with open('requirements.txt', 'a', encoding='utf-8') as f: f.write(f'{name}\n')
    return importlib.import_module(module)

def imports(*modules: tuple[str]) -> t.Callable:
    """Decorator to import modules at runtime, passing them as arguments."""
    def decorator(f):
        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            imported = [_pip_import(module) for module in modules]
            return f(*imported, *args, **kwargs)
        return wrapper
    return decorator

def _arg_line(*args: tuple[str], **kwargs: dict) -> tuple[str]:
    for k, v in kwargs.items(): 
        args += (f'--{k}=\'{v}\'',) if isinstance(v, str) else (f'--{k}={v}',)
    return args

def join_arg_line(args: tuple[str], kwargs: dict) -> str:
    """Joins a list of command-line arguments into a single string."""
    return ' '.join(_arg_line(*args, **kwargs))

def split_arg_line(args: list[str]) -> tuple[tuple, dict]:
    """Converts a command-line list of strings to python function arguments."""
    largs, kwargs = [], {}
    for arg in args:
        if '=' in arg: 
            __key, __value = arg[2:].split('=')
            if __value.startswith("'") and __value.endswith("'"): __value = __value[1:-1]
            kwargs[__key] = __value
        else: largs.append(arg)
    return tuple(largs), kwargs

def _read_const(const:str, fname: str = __file__, ln: int = False) -> str | int | None:
    if not os.path.isfile(fname): return None
    with open(fname, 'r', encoding='utf-8') as f: lines = f.readlines()
    const = f'{const.upper()} ='
    for i, line in enumerate(lines):
        if line.startswith(const): 
            if ln: return i+1
            return line.split(const)[1].strip()
    return None

def _mutate_const(const:str, value: str, fname: str = __file__) -> None:
    # Finds a constant in the source code and replaces it with a new value.
    emit(f"Mutating {const} to {value} in {fname}.")
    if not os.path.isfile(fname): return
    with open(fname, 'r', encoding='utf-8') as f: lines = f.readlines()
    const = f'{const.upper()} ='
    for i, line in enumerate(lines):
        if line.startswith(const):
            lines[i] = f'{const} {value}\n'; break
    with open(fname, 'w', encoding='utf-8') as f: f.writelines(lines)


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
    subprocess.run([_PYTHON, '-m', 'pip', 'install', '-r', 'requirements.txt', '--quiet'])

def _start_py(script: str, *args: list[str], **kwargs: dict) -> subprocess.Popen:
    global _PYTHON
    line_args = [str(a) for a in _arg_line(*args, **kwargs)]
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
    global APP, DEBUG
    DEBUG = _read_const('DEBUG') == 'True'
    if proc and proc.poll() is None: 
        args, kwargs = _stop_py(proc)
        kwargs['opid'] = opid
    else: args, kwargs = [], {}
    return _start_py(f'{APP}.py', *args, **kwargs)

def _watch_over(proc: subprocess.Popen, fn: str) -> t.NoReturn:  
    global DEBUG
    source, old_mtime, stable = _read_file(fn), _mtime_file(fn), True
    while True:
        time.sleep(2.6)
        if (new_mtime := _mtime_file(fn)) != old_mtime:
            mutation, old_mtime = _read_file(fn), new_mtime
            if mutation != source:
                emit(f"Mutation detected. Restart and mark unstable.")
                proc, stable = _restart_py(proc), False
            continue
        if proc.poll() is not None:  
            if proc.returncode == 0: sys.exit(0)  # Halt from below.
            if stable:
                emit(f"Script died {proc.returncode=}. Restart and mark unstable.")
                if not DEBUG: _mutate_const('DEBUG', 'True')
                proc, stable = _restart_py(proc), False
                continue
            halt(f"Script died twice. Stopping watcher.")  # Halt from above.
        if not stable:
            emit(f"Stabilizing {proc.pid=}.")
            if DEBUG: _mutate_const('DEBUG', 'False')
            source, stable = _read_file(fn), True
            

#@# CONTENT GENERATOR

import shutil
import inspect

_WORKDIR = os.path.join(_DIR, '.worker')
_TEMPLATES = {}

# Template syntax: https://docs.makotemplates.org/en/latest/syntax.html
_BASE_HTML = """
<!DOCTYPE html><html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>${q.page_title()}</title><style>${q.app_styles()}</style>
</head>
<body>
    <header><nav>
        <a href='/qaczar.html'>
        <img src="/qaczar.png" alt="QACZAR" width="90" height="90" />
        <h1>${q.ascii_banner('QACZAR')}</h1></a> ${q.nav_links()}
    </nav></header><hr />
    <%block name="content">
        <h2>Roadmap</h2>
        <ol class="ln">${q.enum_file('qaczar.py', prefix='# TODO:')}</ol><hr />
        <!-- ERROR -->
        ${q.render_form(query['form'][0] if 'form' in query else 'sign_guestbook')}
    </%block>
    <%block name="footer">
        <hr /><h3>Files</h3><ul>${q.list_dir()}</ul>
        <footer><a href="/qaczar.py">Powered by the qaczar.py web system.</a></footer>
    </%block>
</body>
</html>
"""	

def _set_workdir(role: str) -> None:
    global _DIR, _WORKDIR
    _WORKDIR = os.path.join(_DIR, f'.{role}')
    if role in ('server', 'worker'):
        if os.path.isdir(_WORKDIR): shutil.rmtree(_WORKDIR)
        os.mkdir(_WORKDIR)

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

def elem(tag: str, content: str=None, **attrs) -> str:
    """Generate an HTML element with optional attributes."""
    if 'data' in attrs: 
        for k, v in attrs['data'].items(): attrs[f'data-{k}'] = v
        del attrs['data']
    attrs = ' '.join(f'{k}="{v}"' for k, v in attrs.items())
    if attrs and not content: return f'<{tag} {attrs}/>'
    if not content: return f'<{tag}/>'
    return f'<{tag} {attrs}>{content}</{tag}>'

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

def _load_template(fname: str) -> object:
    global _TEMPLATES, _DIR, _BASE_HTML
    cached, old_mtime = _TEMPLATES.get(fname, (None, None))
    emit(f"Load template {fname=} {bool(cached)=} {old_mtime=}.")
    if fname == 'qaczar.html':
        if cached: return cached
        if (new_mtime := _mtime_file(fname)) != old_mtime:
            mt = _pip_import('mako.template')
            if fname == 'qaczar.html': tpl = mt.Template(_BASE_HTML)
            else: 
                ml = _pip_import('mako.lookup')
                lookup = ml.TemplateLookup(directories=[_DIR], input_encoding='utf-8')
                # TODO: Consider subclassing mako.template.Template to track more info.
                tpl = mt.Template(filename=fname, lookup=lookup)
            _TEMPLATES[fname] = tpl, new_mtime
            emit(f"Template cache miss {fname=} {new_mtime=}.")
            return tpl
    return _TEMPLATES[fname][0]

def process_html(fname: str, context: dict) -> str:
    """Process a template file with context (uses mako.template)."""	
    # TODO: Test changing the html based on query params.
    template = _load_template(fname)
    content = template.render(**context)
    return write_file(fname, content)

@functools.cache
def extract_api() -> t.Generator[t.Callable, None, None]:
    """Extract all public functions from a module."""
    for name, func in inspect.getmembers(sys.modules[__name__], inspect.isfunction):
        if name.startswith('_'): continue
        if inspect.signature(func).return_annotation in (t.NoReturn, t.Callable): continue
        if not func.__doc__: 
            emit(f"Missing docstring for {name} (ln: {func.__code__.co_firstlineno}).")
        yield func

def _build_input(field: str, param: inspect.Parameter) -> str:
    input_type = 'text'
    if param.annotation is not param.empty:
        if param.annotation is int: input_type = 'number'
        elif param.annotation is bool: input_type = 'checkbox'
    attrs = {'name': field, 'type': input_type, 'title': field}
    if param.default is not param.empty:
        attrs['value'] = param.default
        if param.annotation is bool: attrs['checked'] = 'checked'
    return elem('input', **attrs)

def _active_module(mod_name: str):
    return sys.modules[mod_name if mod_name != APP else __name__]

@functools.cache
def render_form(subpath: str | t.Callable, mod_name: str=None) -> str:
    global APP
    if callable(subpath): subpath = subpath.__name__
    if not mod_name: mod_name = APP
    func = getattr(_active_module(mod_name), subpath)
    form = (f"<form action='/{mod_name}.py/{subpath}' "
            f"method='POST' accept-charset='utf-8' name='{subpath}'>" 
            f"<p class='doc'>{func.__doc__}</p>")
    for name, param in inspect.signature(func).parameters.items():
        if not param.kind in (param.POSITIONAL_ONLY, param.POSITIONAL_OR_KEYWORD): continue
        if name.startswith('_'): continue
        if param.annotation is param.empty: continue
        form += f"<label for='{name}'>{name.upper()}:</label>"
        form += _build_input(name, param) + "<br>"
    form += f"<button type='submit'>EXECUTE</button></form>"
    return form

@functools.cache
def _build_form(mod_name: str, subpath: str) -> str:
    form = render_form(subpath, mod_name)
    return write_file(f"{mod_name}__{subpath}.html" , form)

def _execute_form(mod_name: str, subpath: str, data: dict) -> str:
    func = getattr(_active_module(mod_name), subpath)
    if all(len(v) == 1 for v in data.values()):
        data = {k: v[0] for k, v in data.items()}
    result = func(**data)
    return write_file(f"{mod_name}__{subpath}.html", str(result))

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
    # TODO: The app is being created in the .server directory. Fix this.
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
    content = (f"<h1 class='banner'>{banner}</h1><p>Not found: {fname}</p>"
            f"<pre class='traceback'>{traceback.format_exc()}</pre>"
            f"<hr /><p><a href='/'>Home</a></p>")
    return write_file(fname, content)

# @timed
def _dispatch_processor(fname: str, context: dict) -> str | None:
    global APP
    if '.' not in fname: 
        prefix, suffix = f'{fname}/{fname}', 'html'
        fname = f'{prefix}.{suffix}'
        if not os.path.exists(fname): create_app(fname)
    else: prefix, suffix = fname.split(".", 1)  # Only one dot is allowed.
    # emit(f"Dispatch processor: {fname} {prefix} {suffix}", div='-')
    if '/' in suffix: 
        suffix, subpath = suffix.split('/')
        context['subpath'] = subpath
    if not prefix: prefix = APP
    if (processor := globals().get(f'process_{suffix}')):
        try:
            # TODO: Fix template error: TypeError: unhashable type: 'list'
            # This error happens when using a query string with a form.
            emit(f"Dispatch processor: {fname} {prefix} {suffix}", div='-')
            return processor(f'{prefix}.{suffix}', context)
        except Exception as e:
            emit(f"Error processing {fname}: {type(e)}> {e}", trace=True)
            context['error'] = e
            return _process_error(fname, context)
    return None


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
    """Decorator to record function calls and results in a database."""
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

def _purge_tables():
    global APP, _SCHEMA
    with _connect_db() as db:
        for table in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall():
            if table[0] in _SCHEMA[APP]: continue
            if table[0].startswith(f'{APP}_'): continue
            if table[0].startswith(f'sqlite_'): continue
            emit(f"Purge unused table: {table[0]}")
            db.execute(f"DROP TABLE {table[0]}")
        db.commit()


#@# WEB COMPONENTS

import random

def page_title(title: str = '') -> str:
    """Return a page title, or the default if none is provided."""
    return title if title else f'{APP.upper()}'

def app_styles():
    """Return the CSS styles for the app."""	
    return _read_file(f'qaczar.css', encoding='utf-8')

@imports('pyfiglet')
def ascii_banner(pyfiglet, text:str, font: str='graffiti') -> str:
    """Generate a banner from ASCII text in a random font."""
    if font == 'random':
        font = random.choice(pyfiglet.FigletFont.getFonts())
    banner = pyfiglet.figlet_format(text, font=font) 
    return f"<pre class='ascii' title='Welcome to {text} (Font: {font})'>{banner}</pre>"

@functools.cache
def nav_links() -> str:
    """Generate a list of links to all public functions in a module."""
    global APP
    return '\n'.join(
            f"<a href='/{APP}.html?form={fn.__name__}' title='{fn.__doc__} "
            f"({fn.__code__.co_firstlineno})'>{fn.__name__}</a>" 
            for fn in extract_api())


#@# COMMON FORMS

@recorded
def hello_world(name: str = 'World') -> str:
    """Say hello to the world! Useful as a smoke test."""
    return f"<div class='hello'>Hello, {name}!</div>"

@recorded
def sign_guestbook(email: str, message: str) -> str:
    """Thanks for your visit, please sign our guestbook."""
    # TODO: Consider field validation decorators for POST receiver functions.
    emit(f"Contact from {email}: {message}")
    # return f"Thanks for contacting us, {email}!"
    return f"<p>Thanks for contacting us, {email}! We will be in touch.<p>"
    

#@# HTTPS SERVER

import ssl
import importlib
import datetime as dt
import http.server as hs
import socketserver as ss
import urllib.parse as parse

HOST, PORT, SITE = 'localhost', 9443, 'qaczar.com'

@functools.cache
def _safe_globals() -> dict:
    return {k: v for k, v in globals().items() if not k.startswith('_')}

@imports('cryptography.x509',
    'cryptography.hazmat.primitives.asymmetric.rsa',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.primitives.serialization')
def _build_ssl_certs(x509, rsa, hashes, ser, site=None) -> tuple[str, str]:
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

def _build_server(https: bool = True) -> type:
    if not https: return ss.ThreadingTCPServer
    ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_ctx.load_cert_chain(*_build_ssl_certs())

    class SSLServer(ss.ThreadingTCPServer):
        # TODO: This creates 1 thread per request, which is not ideal. Implement a thread pool.
        def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
            ss.ThreadingTCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate)
            self.socket = ssl_ctx.wrap_socket(self.socket, server_side=True) 

    return SSLServer

@recorded
def access_log(address: str, message: str) -> None:
    """Log an access to the server."""
    emit(f"Access from {address} {message}")

    
def _build_handler() -> type:

    class Q():
        def __init__(self):
            for k, v in _safe_globals().items(): setattr(self, k, v) 
        def __getattr__(self, name):
            # TODO: See if we can include additional information about the caller.
            emit(f"Undefined: q.{name}.")
            return None

    q = Q()

    class EmitHandler(hs.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            access_log(self.address_string(), format % args)

    class Handler(EmitHandler if DEBUG else hs.SimpleHTTPRequestHandler):
        @property
        def content_length(self) -> int:
            return int(self.headers.get('content-length', 0))
        
        def _rfile_read(self, encoding: str = 'utf-8') -> bytes:
            return self.rfile.read(self.content_length).decode(encoding)

        def _build_response(self, method: str = None, _q=q) -> bool:
            global APP
            emit(f"Dispatch {self.client_address[0]} to {self.path}.", div="-")
            self.start = time.time()
            if '//' in self.path: self.path = self.path.replace('//', '/')
            if self.path.endswith('/'): self.path = f'{self.path}{APP}.html'
            if '?' not in self.path: path, qs = self.path, ''
            else: path, qs = self.path.split('?', 1)
            if not path or path == '/': path = f'/{APP}.html'
            # I tried to split off building the entire context, but it was a bad idea.
            context = {
                    'q': _q, 'method': method, 'ts': iso8601(), 
                    'ip': self.client_address[0], 'path': path, 
                    'query': parse.parse_qs(qs), 
                    'form_data': parse.parse_qs(self._rfile_read()),
                    'APP': path.split('/')[1] if '/' in path else None,
            }
            self.work_path = _dispatch_processor(path[1:], context)
            
        def translate_path(self, path: str = None) -> str:
            return super().translate_path(path) if not self.work_path else self.work_path

        def do_HEAD(self) -> None:
            self._build_response('HEAD'); return super().do_HEAD()
            
        def do_GET(self) -> None:
            self._build_response('GET'); return super().do_GET()
        
        def do_POST(self) -> None:
            self._build_response('POST'); return super().do_GET()
        
        def end_headers(self) -> None:
            duration = time.time() - self.start
            self.send_header('Server-Timing', f'miss;dur={duration:.3f}')
            self.send_header('Cache-Control', f'Etag: {_mtime_file(self.path)}')
            return super().end_headers()
        
        def send_header(self, keyword: str, value: str) -> None:
            if keyword.lower() == 'content-type' and 'text' in value and 'encoding' not in value:
                value = f"{value}; charset=utf-8"
            elif keyword == 'Server': value = f"{value} (qaczar.py)"
            # emit(f"Sent header {keyword}: {value}")
            return super().send_header(keyword, value)

    return Handler


#@#  SELF TESTING

_COUNTER = 0

@imports('urllib3')
def _request_factory(urllib3, app:str=None):
    # TODO: Design a string for the user-agent and use it to track tests.
    global HOST, PORT
    http = urllib3.PoolManager(cert_reqs='CERT_REQUIRED', ca_certs=_build_ssl_certs()[0])
    def _request(fname:str, data:dict = None, status:int = 200):
        global _COUNTER
        if app: fname = f"{app}/{fname}"
        url = f"https://{HOST}:{PORT}/{fname}"
        r = http.request('POST' if data else 'GET', url, fields=data, timeout=30)
        assert r.status == status, f"Request to {url} failed with status {r.status}"
        # emit(f"Request {_COUNTER} to {url} succeeded with status {r.status}")
        _COUNTER += 1
        return r.data.decode('utf-8')
    return _request
    
def test_server(*args, **kwargs) -> t.NoReturn:
    # TODO: Test other special paths such as blank, /, etc.
    # TODO: Test submitting a form (ie. sign_guestbook).
    global APP
    request = _request_factory()
    assert 'qaczar' in request(f'{APP}.html')
    assert 'qaczar' in request(f'{APP}.py')
    assert 'qaczar' in request(f'/')
    assert 'qaczar' in request(f'')
    assert 'qaczar' in request(f'//')


#@#  REPOSITORY

def _commit_source() -> t.NoReturn:
    # TODO: Create missing branch if not exists when pushing to git.
    global _BRANCH
    os.system('git add .')
    os.system('git commit -m "auto commit" -q')
    os.system(f'git push origin {_BRANCH} -q')
    emit(f"Source committed to {_BRANCH}.")


#@# COMMON ROLES

def watcher_role(*args, next: str = None, **kwargs) -> t.NoReturn:
    global APP
    if not next: raise ValueError('next role was not defined')
    kwargs['role'] = next
    _watch_over(_start_py(f'{APP}.py', *args, **kwargs), f'{APP}.py')

def server_role(*args, host=HOST, port=PORT, **kwargs) -> t.NoReturn:
    global APP
    _purge_tables()
    server_cls = _build_server()
    handler_cls = _build_handler()
    with server_cls((host, int(port)), handler_cls) as httpd:
        emit(f"Server ready at https://{host}:{port}")
        atexit.register(httpd.shutdown)
        kwargs['role'] = 'tester'
        kwargs['suite'] = 'server' if 'suite' not in kwargs else kwargs['suite']
        _start_py(f'{APP}.py', *args, **kwargs)
        httpd.serve_forever()

def tester_role(*args, suite: str = None, **kwargs) -> t.NoReturn:
    # TODO: Add some automatic tests to prevent public API regressions.
    global _MTIME
    time.sleep(1)  # Wait for server to start.
    emit(f"Running test suite for '{suite}'.")
    passed = 0
    for test in globals().keys():
        if test.startswith(f'test_{suite}'): 
            emit(f"Running {test=}...")
            globals()[test](*args, **kwargs)
            passed += 1
        if _mtime_file(f'{APP}.py') != _MTIME: break
    else:
        emit(f"Tests for '{suite}' passed: {passed}.")
        _commit_source()

def worker_role(*args, **kwargs) -> t.NoReturn:
    pass


#@# DISPATCHER

def _role_dispatcher(role: str, args: tuple, kwargs: dict) -> t.NoReturn:
    global DEBUG
    _set_workdir(role)
    opid = kwargs.pop('opid', None)  # If we receive opid it means we are being watched.
    emit(f"Dispatch role='{__role}' args={__args} kwargs={__kwargs} watch by {opid=}.")
    function = globals().get(f"{role}_role")
    if function is None: raise ValueError(f"Role '{role}' is not defined.")
    try:
        function(*args, **kwargs)
    except AssertionError as e:
        (halt if DEBUG else emit)(f"Assertion failed: {e}")
    except KeyboardInterrupt:
        halt("Interrupted by user.")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        _setup_environ()
        __role, __args, __kwargs = 'watcher', [], {'next': 'server'}
    else:
        __args, __kwargs = split_arg_line(sys.argv[1:])
        __role = __kwargs.pop('role')  # It's ok to fail if role is not defined.
    _role_dispatcher(__role, __args, __kwargs)
