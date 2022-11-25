#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that does everything.
# H. V. D. C. by Rafa Guillén (arthexis@gmail.com) 2022-2023

# TODO: Work on the control form and general styling.


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
    return re.sub(r'\s+', ' ', text)[:30] if text else 'N/A'

def md5(blob):
    if blob := blob.encode('utf-8') if isinstance(blob, str) else blob:
        return hashlib.md5(blob).hexdigest()

def seed_mtime(topic, src='seeds'):
    global DIR
    try:
        return int(os.path.getmtime(f'{DIR}/{src}/{topic}'))
    except FileNotFoundError: return 0

def _plant_seed(c, fname, topic, mtime, encoding):
    if seed := fread(f'{DIR}/seeds/{fname}', e=encoding):     
        ts, new_md5, mtime = isotime(), md5(seed), mtime or seed_mtime(fname)
        num = c.execute(f'INSERT INTO {topic} (ts, article, md5, mtime) VALUES (?, ?, ?, ?)', 
            (ts, seed, new_md5, mtime)).lastrowid
        emit(f"Seed {fname} uploaded ({len(seed)} bytes).")
        PALACE.commit()
        return num, ts, seed, new_md5, mtime
    
Article = collections.namedtuple('Article', 'topic num ts article')

def palace_recall(topic, /, fetch=True, store=None, encoding='utf-8'):
    global PALACE, TOPICS, DIR
    assert topic and re.match(r'^[a-zA-Z0-9_.]+$', topic), f'Invalid recall {topic=}.'
    fname, topic = topic, topic.lower().replace('.', '__')
    short = f'"{summary(store)}..." ({len(store)} bytes)' if store else 'N/A'
    emit(f'Palace recall {topic=} {fetch=} {type(store)=} {encoding=}.') 
    c = PALACE.cursor()
    if not TOPICS:
        c.execute('SELECT name FROM sqlite_master WHERE type="table" AND name not LIKE "sqlite_%"')
        TOPICS.extend(t[0] for t in c.fetchall())
    if topic not in TOPICS:            
        atype = 'TEXT' if isinstance(store, str) else 'BLOB' if isinstance(store, bytes) else 'NULL'
        c.execute(f'CREATE TABLE IF NOT EXISTS {topic} ('
                f'num INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, article {atype}, md5 TEXT, mtime INTEGER)')
        emit(f"Created table {topic}.")
        _plant_seed(c, fname, topic, None, encoding)
        TOPICS.append(topic)
    found = c.execute(f'SELECT num, ts, article, md5, mtime FROM {topic} '
        f'ORDER BY ts DESC LIMIT 1').fetchone() if fetch else None
    if found and found[4] and (mtime := seed_mtime(fname)) > found[4]:
        found = _plant_seed(c, fname, topic, mtime, encoding)
    next_md5 = md5(store)
    if store and (not found or found[3] != next_md5):
        if rowid := c.execute(f'INSERT INTO {topic} (ts, article, md5) VALUES (?, ?, ?)', 
                (isotime(), store, next_md5)).lastrowid:
            PALACE.commit()
            emit(f'Insert comitted {topic=} {rowid=}.')
        if not fetch: return rowid  # Return num of new articles if not fetching.
    if found: return Article(topic, found[0], found[1], found[2])  # topic, num, ts, article



# TODO: Function that creates relationships between 2 articles.
# TODO: Then, it prunes old articles with no relationships.
    

# V.

import urllib.parse
from wsgiref.simple_server import make_server, WSGIRequestHandler

IGNORE = ('favicon.ico', )

# Main entrypoint for the user AND delegates. UI == API.
def facade_main(environ, respond):
    global SITE
    start = time.time()
    emit(f'--*-- Incoming request {environ["REQUEST_METHOD"]} {environ["PATH_INFO"]} from {environ["REMOTE_ADDR"]} --*--')
    try:
        layers = [p for p in re.split(r'[/]+', environ['PATH_INFO']) if p]
        if len(layers) == 1 and '.' in (fname := layers[0]):
            yield from standalone_file(fname, respond)
        else:
            respond('200 OK', [('Content-type', f'text/html; charset=utf-8')])
            yield f'<!DOCTYPE html><meta charset="utf-8"><head><title>{SITE}</title>'.encode('utf-8')
            if css := palace_recall('qaczar.css'): yield f'<style>{css.article}</style>'.encode('utf-8')
            yield (f'</head><body><nav><h1><a href="/">{SITE}</a>!</h1>'.encode('utf-8'))
            if cmd := facade_command_form(environ, layers): yield cmd
            yield b'</nav><main>'
            if not layers: yield from facade_overview(environ)
            for layer in layers:
                if found := palace_recall(layer): yield hypertext(found.article)
            yield (f'</main><footer>A programmable grimoire by Rafa Guill&eacute;n (arthexis)' 
                f'</footer></body></html>').encode('utf-8')
    finally:
        emit(f"Request completed in {int((time.time() - start)*1000)} ms.")

def facade_command_form(environ, layers):
    try:    
        if environ['REQUEST_METHOD'] == 'POST':
            data = environ['wsgi.input'].read(int(environ.get('CONTENT_LENGTH', 0))).decode('utf-8')
            emit(f'Data received: {layers=} {data=}')
            if layers and (topic := layers[0]):
                found = palace_recall(topic, store=data)
                emit(f'Article stored from POST {found.num=}.')
        return (f'<form id="cmd-form" method="post">' 
                f'<input type="text" id="cmd" name="cmd" size=70></form>').encode('utf-8')
    except Exception as e:
        emit(f'Error processing command form {e=}.')
        return b'<strong>Command form error.</strong>'
    
def facade_overview(environ):
    global PALACE, TOPICS
    c = PALACE.cursor()
    yield f'<h2>Palace overview</h2><ul>'.encode('utf-8')
    for topic in TOPICS:
        c.execute(f'SELECT num, ts, article, md5, mtime FROM {topic} ORDER BY ts DESC LIMIT 1')
        if found := c.fetchone():
            try:
                stored, ts = len(found[2]), found[1]
                yield f'<li><a href="/{topic}">{topic}</a> {ts} : {stored} bytes </li>'.encode('utf-8')
            except Exception as e:
                yield (f'<li><a href="/{topic}">{topic}</a> : <strong>NO CONTENT</strong></li>').encode('utf-8')
    yield f'</ul>'.encode('utf-8')
        
def standalone_file(fname, respond):
    if not (blob := palace_recall(fname, encoding=None)):
        respond('404 Not Found', [('Content-type', 'text/plain')])
        yield iter([b''])
    blob = blob[3]
    mimetype = mimetypes.guess_type(fname, strict=False)[0] or 'application/octet-stream'
    respond('200 OK', [('Content-Type', mimetype), ('Content-Length', str(len(blob)))])
    emit(f'Served file {fname=} {mimetype=} {len(blob)=} bytes.')
    for i in range(0, len(blob), 1024):
        yield blob[i:i+1024]

# TODO: Create a function that generates arbitrary HTML tables for formatting.
def table_layout(rows, cols, data):
    return (f'<table><tr><th>{f"</th><th>".join(cols)}</th></tr>'
        f'<tr><td>{f"</td><td>".join(data)}</td></tr></table>').encode('utf-8')

def hypertext(article):
    # TODO: Figure a better way to encapsulate binary content in html.
    if not article: return b' '
    topic, num, ts, article = article
    # Extract the prefix, the last part after __
    prefix = article.split('__')[-1]
    if prefix in ('css', 'py'):
        article = article.replace("\n", "</li><li>")
        article = f'<ol><li><pre>{article}</pre></li></ol>'
    return (f'<article id="{topic}__{num}" data-ts="{ts}">' 
        f'{article}</article>').encode('utf-8')

class Unhandler(WSGIRequestHandler):
    def log_request(self, code=None, size=None): pass

if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite', isolation_level='IMMEDIATE')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    palace_recall('qaczar.py', store=BODY)
    with make_server(HOST, PORT, facade_main, handler_class=Unhandler) as s:
        emit(f'Facade ready at http://{HOST}:{PORT}/')
        create_fork(sys.argv[1], 'certify_build')
        s.serve_forever(poll_interval=1)


# H.

# TODO: Add a function to extract info from external sources.

import urllib.request
from contextlib import contextmanager

@contextmanager
def request_facade(*args, upload=None):
    assert all(urllib.parse.quote(arg) == arg for arg in args), f"Invalid facade request {args=}"
    url = f'http://{HOST}:{PORT}/{"/".join(args)}'
    emit(f'Send request: {url=} {upload=}')
    try:
        upload = upload.encode('utf-8') if upload else None
        with urllib.request.urlopen(url, data=upload, timeout=6) as r:
            if r.status == 200: yield r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        emit(f'HTTPError: {e.code}'); raise e

def run_silently(cmd):
    try:
        return subprocess.run(cmd, shell=True, check=True, capture_output=True)
    except subprocess.CalledProcessError as e:
        emit(f'Command failed: {e=}')
    
def certify_build():
    global BRANCH
    # TODO: Add a call to facade to update the roadmap topic with BODY TODOs. 
    # Loop over each line in BODY enumerating the TODOs and store them in a list. 
    roadmap = []
    for ln, line in enumerate(BODY.splitlines()):
        if line.strip().startswith('# TODO:'):
            roadmap.append(f'{ln+1}: {line.strip()[7:]}')
    roadmap = '\n'.join(roadmap)
    with request_facade('roadmap', upload=roadmap) as r:
        emit(f'Facade response: {len(r)=} bytes.')
        run_silently(['git', 'add', '.'])
        run_silently(['git', 'commit', '-m', 'Automatic commit by certify_build.'])
        s = run_silently(['git', 'push', 'origin', BRANCH])
        emit(f'Git sync complete ({s.returncode=}).')
    return 'SUCCESS'

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

