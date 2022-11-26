#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that does everything by itself.
# H. V. D. C. by Rafa Guillén (arthexis@gmail.com) 2022-2023

# IMPORTANT REQUIREMENTS:
# 1. Keep the width to less than 100 characters.
# 2. Use functions to provide modularity and information hiding.


import os
import sys
import time
import atexit
import subprocess


SITE = 'qaczar.com'
RUNLEVEL = len(sys.argv)
DIR = os.path.dirname(__file__)
BRANCH = 'main'


def isotime(t=None): 
    return time.strftime('%Y-%m-%d %H:%M:%S', t or time.gmtime())

def emit(verse): 
     print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}] [{isotime()}] {verse}')

def fread(fn, e='utf-8'):
    try: 
        with open(fn, 'r' if e else 'rb', encoding=e) as f:  return f.read()
    except FileNotFoundError: return None 

BODY = fread(__file__)
assert BODY, 'Bodyplan not found.'


# C.

HOST, PORT = os.environ.get('HOSTNAME', 'localhost'), 8080 

def create_fork(*args, old=None):
    assert len(args) > 0
    if old is not None:
        old.terminate(); old.wait()
        atexit.unregister(old.terminate)
    if not (s := subprocess.Popen([sys.executable, __file__, *[str(a) for a in args]])):
        raise RuntimeError('Failed to create fork.')
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"Created fork {' '.join(str(a) for a in args)} {s.pid=}.")
    return s

def watch_over(s):  # aka. The Crown
    global BODY
    while True:
        stable, mtime = True, os.path.getmtime(__file__)
        while True:
            time.sleep(2.6)  # A reasonable time for take backs.
            if os.path.getmtime(__file__) != mtime:
                mutation, mtime = fread(__file__), os.path.getmtime(__file__)
                if mutation != BODY:
                    emit(f"Mutation detected {len(mutation)=} {len(BODY)=}. Restarting.")
                    s, stable = create_fork(*s.args, old=s), False
                continue
            if s.poll() is not None:
                if stable:
                    emit(f"Fork died {s.args=} {s.pid=}. Restarting.")
                    s, stable = create_fork(*s.args, old=s), False
                    continue
                emit("Crown unstable, aborting. Check qaczar.py for errors.")
                sys.exit(1)
            stable = True

if __name__ == "__main__" and RUNLEVEL == 1:
    emit('----------------------------------------')
    try:    
        watch_over(create_fork(f'{HOST}:{PORT}'))
    except KeyboardInterrupt:
        emit(f"Keyboard interrupt {RUNLEVEL=}"); raise
    except RuntimeError:
        emit(f'Crown failure, unable to start.'); raise

# D.

import re
import hashlib
import sqlite3
import mimetypes
import collections

PALACE, TOPICS = None, []

def summary(text):
    if not text or not isinstance(text, str): return 'N/A'
    return re.sub(r'\s+', ' ', text)[:54] if text else 'N/A'

def md5(blob):
    if blob := blob.encode('utf-8') if isinstance(blob, str) else blob:
        return hashlib.md5(blob).hexdigest()

def _seed_mtime(topic, src='seeds'):
    global DIR
    try:
        return int(os.path.getmtime(f'{DIR}/{src}/{topic}'))
    except FileNotFoundError: return 0

def _plant_seed(c, fname, topic, mtime, encoding):
    if seed := fread(f'{DIR}/seeds/{fname}', e=encoding):     
        ts, new_md5, mtime = isotime(), md5(seed), mtime or _seed_mtime(fname)
        num = c.execute(f'INSERT INTO {topic} (ts, article, md5, mtime) VALUES (?, ?, ?, ?)', 
            (ts, seed, new_md5, mtime)).lastrowid
        emit(f"Seed {fname} uploaded ({len(seed)} bytes).")
        PALACE.commit()
        return num, ts, seed, new_md5, mtime
    
Article = collections.namedtuple('Article', 'topic num ts article')

def palace_recall(topic, /, fetch=True, store=None, encoding='utf-8'):
    global PALACE, TOPICS, DIR
    assert topic and re.match(r'^[a-zA-Z0-9_.]+$', topic), f'Invalid recall {topic=}.'
    fname, topic = topic.lower().replace('__', '.'), topic.lower().replace('.', '__')
    emit(f'Palace recall {topic=} {fetch=} {type(store)=} {encoding=}.') 
    c = PALACE.cursor()
    if not TOPICS:
        c.execute('SELECT name FROM sqlite_master WHERE '
            'type="table" AND name not LIKE "sqlite_%"')
        TOPICS.extend(t[0] for t in c.fetchall())
    if topic not in TOPICS:            
        atype = 'TEXT'
        if isinstance(store, bytes): atype = 'BLOB'
        c.execute(f'CREATE TABLE IF NOT EXISTS {topic} ('
                f'num INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, '
                f'article {atype}, md5 TEXT, mtime INTEGER)')
        emit(f"Created table {topic}.")
        _plant_seed(c, fname, topic, None, encoding)
        TOPICS.append(topic)
    found = c.execute(f'SELECT num, ts, article, md5, mtime FROM {topic} '
        f'ORDER BY ts DESC LIMIT 1').fetchone() if fetch else None
    if found and found[4] and (mtime := _seed_mtime(fname)) > found[4]:
        found = _plant_seed(c, fname, topic, mtime, encoding)
    next_md5 = md5(store)
    if store and (not found or found[3] != next_md5):
        if rowid := c.execute(f'INSERT INTO {topic} (ts, article, md5) VALUES (?, ?, ?)', 
                (isotime(), store, next_md5)).lastrowid:
            PALACE.commit()
            emit(f'Insert comitted {topic=} {rowid=}.')
        if not fetch: return rowid
    if found: return Article(topic, found[0], found[1], found[2])  # topic, num, ts, article


def palace_summary():
    global PALACE
    c = PALACE.cursor()
    c.execute('SELECT name FROM sqlite_master WHERE '
        'type="table" AND name not LIKE "sqlite_%"')
    for topic in [t[0] for t in c.fetchall()]:
        c.execute(f'SELECT num, ts, article FROM {topic} ORDER BY ts DESC LIMIT 1')
        found = c.fetchone()
        # The format of the output is [(topic, count, ts, summary)].
        if found: yield (topic, found[0], found[1], summary(found[2]))


# V.

import secrets
import urllib.parse
from wsgiref.simple_server import make_server, WSGIRequestHandler

SECRET = secrets.token_bytes()

def hyper(text, wrap=None):
    if wrap: yield f'<{wrap}>'.encode('utf-8') 
    if text:
        if isinstance(text, bytes): yield text
        elif isinstance(text, str): yield text.encode('utf-8')
        elif isinstance(text, Article): yield from hyper(text.article)
        elif isinstance(text, (list, tuple)): 
            yield from (hyper(c) for c in text)
        else: emit(f'Unable to hyper text {type(text)=} {text=}.')
    yield b''
    if wrap: yield f'</{wrap}>'.encode('utf-8') 

# Main entrypoint for the user AND delegates. UI == API.
def facade_main(env, resp):
    global SITE
    start = time.time()
    method, path, origin = env["REQUEST_METHOD"], env["PATH_INFO"], env["REMOTE_ADDR"]
    emit(f'--*-- Incoming {method=} {path=} from {origin=} --*--')
    try:
        if origin != '127.0.0.1':
            emit(f'Invalid remote address {origin}.')
            resp('403 Forbidden', [('Content-Type', 'text/plain')]); yield b''
        else:
            layers = [p for p in re.split(r'[/]+', path) if p]
            if len(layers) == 1 and '.' in (fname := layers[0]):  
                if (found := palace_recall(fname, encoding=None)) and (blob := found.article):
                    iwrapped, mt, = _facade_wrap_file(fname, blob)
                    resp('200 OK', [('Content-Type', mt), ('Content-Length', str(len(blob)))])
                    yield from iwrapped
                else:
                    resp('404 Not Found', [('Content-Type', 'text/plain')])
                    yield b'Not found.'
            else:
                cmd = _facade_command_form(env, layers)
                resp('200 OK', [('Content-type', f'text/html; charset=utf-8')])
                if not cmd: yield b'200 Ok.' 
                else:
                    yield from hyper(f'<!DOCTYPE html><head><title>{SITE}</title>')
                    if js := palace_recall('qaczar.css'): 
                        yield from hyper(js.article, 'style')
                    links = _facade_quick_links(layers)
                    yield from hyper(f'</head><body><nav><h1><a href="/">{SITE}</a>!</h1>' 
                        f'{"".join(links)}{cmd}</nav><main>')
                    # --- Main HTML content starts here. ---
                    if not layers and (overview := palace_recall('roadmap__txt')): 
                        yield from hyper(_facade_wrap_article(overview))
                        yield from hyper(_facade_palace_summary())
                    for layer in layers:
                        if (found := palace_recall(layer)) and (article := found.article):
                            yield from hyper(_facade_wrap_article(article, topic=layer))
                    yield from hyper(
                        f'</main><footer>A programmable grimoire by Rafa Guill&eacute;n ' 
                        f'(arthexis). Served {isotime()}.</footer></body></html>')
                    if js := palace_recall('qaczar.js'): 
                        yield from hyper(js.article, 'script')
    # Don't catch exceptions here, or they will be hidden in the logs.
    finally:
        emit(f"Request completed in {int((time.time() - start)*1000)} ms.")

def _facade_wrap_file(fname, article):
    article = article if isinstance(article, bytes) else article.encode('utf-8')
    mimetype = mimetypes.guess_type(fname, strict=False)[0] or 'application/octet-stream'
    assert isinstance(article, bytes), f'File {fname=} {type(article)=} {article=}.'
    return (article[i:i+1024] for i in range(0, len(article), 1024)), mimetype

def _facade_palace_summary():
    data = "".join(f"<tr><td>{s[0]}</td><td>{s[1]}</td><td>{s[2]}</td><td><q>{s[3]}</q></td></tr>" 
        for s in list(palace_summary()))
    return (f'<article><table><tr><th>Topic</th><th>Count</th><th>Timestamp</th><th>Summary</th>' 
        f'</tr>{data}</table></article>')

def _facade_quick_links(layers):
    # TODO: Add a link to a more detailed roadmap (research ideas?)
    return f'[<a href="/qaczar__py">Source</a>]'

def _facade_command_form(env, layers):
    if env['REQUEST_METHOD'] == 'POST':
        data = env['wsgi.input'].read(int(env.get('CONTENT_LENGTH', 0))).decode('utf-8')
        emit(f'Data received: {layers=} {summary(data)=}')
        if layers and (topic := layers[0]):
            found = palace_recall(topic, store=data)
            emit(f'Article stored from POST {found.num=}.')
            return None
    # TODO: GET commands should be processed before the result is stored.
    # TODO: Contextual buttons should be added after the textarea.
    return (f'<form id="cmd-form" method="post">'
        f'<textarea id="cmd" name="cmd" cols=70 rows=1></textarea></form>')

def _facade_wrap_article(found, topic=None, mode='ol'):
    # TODO: Make sure python scripts are rendered correctly (syntax highlighting).
    # TODO: Fix invalid article rendering for python scripts.
    assert mode in ('ol', 'ul', 'table'), f'Invalid mode {mode=}.'
    if not found: return None
    if isinstance(found, str): found = Article('', 0, 0, found)
    assert isinstance(found, Article), f'Invalid article {type(found)=} {found=}.'
    topic = topic or found.topic or 'Untitled'
    prefix = re.search(r'__|\.([^.]+)$', topic).group(1) or 'txt'
    emit(f'Wrapping {topic=} {prefix=} {found.num=}.')
    if prefix in ('txt', 'css', 'py'):
        content = ('<ol><li><pre>' + 
            re.sub(r'\n', r'</pre></li><li><pre>', found.article) + '</pre></li></ol>')
    elif prefix == 'html':
        content = f'<div>{found.article}</div>'
    else:
        content = f'<pre>{found.article}</pre>'
    title = f'<h2>Latest {topic.rsplit("__")[0]}</h2>'
    return f'<article>{title}<div>{content}</div></article>'

class Unhandler(WSGIRequestHandler):
    def log_request(self, *args, **kwargs): pass

if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite', isolation_level='IMMEDIATE')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    palace_recall('qaczar__py', store=BODY)
    # TODO: Add another delegate to generate SSL certificates if missing.
    with make_server(HOST, PORT, facade_main, handler_class=Unhandler) as s:
        emit(f'Facade ready. Serving on http://{HOST}:{PORT}/')
        create_fork(sys.argv[1], 'certify_build')
        s.serve_forever(poll_interval=1)


# H.

import urllib.request

def request_facade(*args, upload=None):
    assert all(urllib.parse.quote(arg) == arg for arg in args), f"Invalid request {args=}"
    url = f'http://{HOST}:{PORT}/{"/".join(args)}'
    emit(f'Send request: {url=} {summary(upload)=}')
    try:
        upload = upload.encode('utf-8') if upload else None
        with urllib.request.urlopen(url, data=upload, timeout=6) as r:
            return r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        emit(f'HTTPError: {e.code}'); raise e

def chain_run(*cmds):
    s = None
    # TODO: Produce a report that can be uploaded to the palace.
    for cmd in cmds:
        try:
            s = subprocess.run(cmd, shell=True, check=True, capture_output=True)
            if s.returncode != 0: return s.returncode
        except (subprocess.CalledProcessError, RuntimeError) as e:
            emit(f'Command error: {e=}')
            return s.returncode if s else -1
    return s.returncode

# TODO: Create a new kind of scheduler (cron) delegate.
    
def certify_build():
    global BRANCH
    # Use request_facade to get the overview and check the response contains all the CSS text.
    r = request_facade()
    css_content = palace_recall('qaczar__css').article
    assert css_content in r, f'CSS not found in palace overview {summary(r)}'
    roadmap = []
    for ln, line in enumerate(BODY.splitlines()):
        if line.strip().startswith('# TODO:'):
            roadmap.append(f'@{ln+1:04d} {line.strip()[7:]}')
    roadmap = '\n'.join(roadmap)
    r = request_facade('roadmap__txt', upload=roadmap)
    emit(f'Facade response to roadmap.txt upload: {r}')
    found = palace_recall('roadmap__txt')
    if not found or found[3] != roadmap:
        emit('Roadmap not updated properly.'); sys.exit(1)
    else:
        emit('Roadmap update validated.')
    # TODO: Store platform information related to each build test.
    # TODO: Check that qaczar.py is loading properly in the web.
    # TODO: Consider encrypting the contents of the palace before storing them.
    # TODO: New delegate that runs a git pull and checks the result.
    last_result = chain_run(
            ['git', 'add', '.'],
            ['git', 'commit', '-m', 'Automatic commit by certify_build.'],
            ['git', 'push', 'origin', BRANCH])
    emit(f'Git sync complete ({last_result=}).')
    return 'SUCCESS' if last_result == 0 else 'FAILURE'

if __name__ == "__main__" and RUNLEVEL == 3:
    GOAL = sys.argv[2]
    emit(f'Delegate of <{HOST}:{PORT}> preparing to <{GOAL}>.')
    assert PALACE is None, 'Palace already connected. Not good.'
    PALACE =  sqlite3.connect('file:p.sqlite?mode=ro', uri=True)
    for task in GOAL.split(':'):
        try: 
            task = globals()[GOAL]
        except KeyError as e:
            emit(f'No such task <{GOAL=}>.'); sys.exit(1)
        try:
            if result := task():
                emit(f'Task <{GOAL}> completed: {result=}')
                continue
            emit(f'Task <{GOAL}> executed with no result.'); sys.exit(1)
        except Exception as e:
            emit(f'Task error: {e=}'); sys.exit(1)

# TODO: Think about how to deploy to AWS after SSL is working.            
# TODO: Think of new functions to add to qaczar.
