#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that does everything.
# H. V. D. C. by Rafa Guillén (arthexis@github) 2022-2023


import os
import sys
import time
import atexit
import subprocess


SITE = 'qaczar.com'
RUNLEVEL = len(sys.argv)
DIR = os.path.dirname(__file__)


def isotime(): 
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(verse): 
     print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}] [{isotime()}] {verse}')

def fread(fn, encoding='utf-8'):
    try: 
        with open(fn, 'r' if encoding else 'rb', encoding=encoding) as f: 
            return f.read()
    except FileNotFoundError: return None 

BODY = fread(__file__)
assert BODY, 'Bodyplan not found.'


# C.

HOST, PORT = os.environ.get('HOSTNAME', 'localhost'), 8080 

def create_fork(*args, old=None):
    assert len(args) > 0
    if old is not None:
        old.terminate()
        old.wait()
        atexit.unregister(old.terminate)
    if not (s := subprocess.Popen([sys.executable, __file__, *[str(a) for a in args]])):
        raise RuntimeError('Failed to create fork.')
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"Created fork {' '.join(str(a) for a in args)} {s.pid=}.")
    return s

def watch_over(s):  # aka. the crown
    global BODY
    while True:
        stable, mtime = True, os.path.getmtime(__file__)
        while True:
            time.sleep(2.6)  
            if os.path.getmtime(__file__) != mtime:
                mutation, mtime = fread(__file__), os.path.getmtime(__file__)
                if mutation != BODY:
                    emit(f"Mutation {len(mutation)=} {len(BODY)=}. Restarting.")
                    s, stable = create_fork(*s.args, old=s), False
                continue
            if s.poll() is not None:
                if stable:
                    emit(f"Fork died {s.args=} {s.pid=}. Restarting.")
                    s, stable = create_fork(*s.args, old=s), False
                    continue
                else:
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

PALACE, TOPICS, SEEDED = None, [], {}

def summary(text):
    return re.sub(r'\s+', ' ', text)[:30] if text else 'N/A'

def md5(blob):
    if blob := blob.encode('utf-8') if isinstance(blob, str) else blob:
        return hashlib.md5(blob).hexdigest()

def seed_mtime(topic):
    global DIR
    return os.path.getmtime(f'{DIR}/seeds/{topic}')


def palace_recall(topic, /, fetch=True, store=None, encoding='utf-8'):
    # TODO: Handle requests for binary files.
    global PALACE, TOPICS, SEEDED, DIR
    assert topic and re.match(r'^[a-zA-Z0-9_.]+$', topic), f'Invalid recall {topic=}'
    fn, topic = topic, topic.lower().replace('.', '__')
    short = f'"{summary(store)}..." ({len(store)} bytes)' if store else 'N/A'
    emit(f'Recall {topic=} {fetch=} {short=}.')
    c = PALACE.cursor()
    if not TOPICS:
        c.execute('SELECT name FROM sqlite_master WHERE type="table" AND name not LIKE "sqlite_%"')
        TOPICS.extend(t[0] for t in c.fetchall())
    if topic in SEEDED and (mtime := seed_mtime(fn)) != SEEDED[topic]:
        seed = fread(f'{DIR}/seeds/{fn}', encoding=encoding)
        c.execute(f'INSERT INTO {topic} (ts, article, md5) VALUES (?, ?, ?)',
            (isotime(), seed, md5(seed)))
        PALACE.commit()
        SEEDED[topic] = mtime
        emit(f'Seed reloaded {topic=} {mtime=}.')
    if topic not in TOPICS:            
        atype = 'TEXT' if isinstance(store, str) else 'BLOB' if isinstance(store, bytes) else 'NULL'
        c.execute(f'CREATE TABLE IF NOT EXISTS {topic} ('
            f'num INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, article {atype}, md5 TEXT)')
        if seed := fread(f'{DIR}/seeds/{fn}', encoding=encoding):  # ERROR
            c.execute(f'INSERT INTO {topic} (ts, article, md5) VALUES (?, ?, ?)', 
                (isotime(), seed, md5(seed)))
            SEEDED[topic] = os.path.getmtime(f'{DIR}/seeds/{fn}')
            emit(f'Seeded {topic=} {SEEDED[topic]=} {md5(seed)}.')
            PALACE.commit()
        emit(f"Created table {topic}.")
        TOPICS.append(topic)
    found = c.execute(f'SELECT num, ts, article, md5 FROM {topic} '
        f'ORDER BY ts DESC LIMIT 1').fetchone() if fetch else None
    next_md5 = md5(store)
    if store and (not found or found[3] != next_md5):
        rowid = c.execute(f'INSERT INTO {topic} (ts, article, md5) VALUES (?, ?, ?)', 
            (isotime(), store, next_md5)).lastrowid
        PALACE.commit()
        emit(f'Insert comitted {topic=} {rowid=}')
        if not fetch: return rowid  # Return num of new articles if not fetching.
    if found: return topic, found[0], found[1], found[2]  # topic, num, ts, article


# TODO: Function that creates relationships between two articles.
# TODO: Process that prunes old articles with no relationships.
    

# V.

from wsgiref.simple_server import make_server, WSGIRequestHandler

IGNORE = ('favicon.ico', )

# Main entrypoint for the WSGI server.
def main_facade(env, respond):
    global SITE
    start = time.time()
    emit(f'Incoming request {env["PATH_INFO"]}')
    try:
        # TODO: Send binary files (images, fonts, etc.) as is.
        layers = [p for p in re.split(r'[/]+', env['PATH_INFO']) if p]
        if len(layers) == 1 and '.' in (fn := layers[0]):
            if blob := palace_recall(fn, encoding=None):
                blob = blob[3]
                mimetype = mimetypes.guess_type(fn, strict=False)[0] or 'application/octet-stream'
                respond('200 OK', [('Content-Type', mimetype), ('Content-Length', str(len(blob)))])
                emit(f'Served file {fn=} {mimetype=} {len(blob)=} bytes.')
                # Yield blob in blocks of 1024 bytes.
                for i in range(0, len(blob), 1024):
                    yield blob[i:i+1024]
            emit(f'404 Not found {fn=}')
        # We could return other statuses, but the standard doesn't force us to.
        respond('200 OK', [('Content-type', f'text/html; charset=utf-8')])
        yield f'<!DOCTYPE html><meta charset="utf-8"><title>{SITE}</title>'.encode('utf-8')
        if css := hypertext(palace_recall('qaczar.css')): yield css
        yield f'<body><head><h1><a href="/">{SITE.upper()}</a>!</h1><main>'.encode('utf-8')
        for layer in layers:
            if article := palace_recall(layer):
                yield hypertext(article)
        yield f'</main></body>'.encode('utf-8')
        if js := hypertext(palace_recall('qaczar.js')): yield js
        yield f'</html>'.encode('utf-8')
    finally:
        emit(f"Request completed in {int((time.time() - start)*1000)} ms.")

def hypertext(article):
    # TODO: Figure a way to encapsulate binary content in html.
    if not article: return b' '
    topic, num, ts, article = article
    if topic.endswith('__css'):
        return f'<style>{article}</style>'.encode('utf-8')
    elif topic.endswith('__js'):
        return f'<script>{article}</script>'.encode('utf-8')
    elif topic.endswith('__py'):
        article = article.replace("\n", "</li><li>")
        article = f'<ol><li>{article}</li></ol>'
    return (f'<article id="{topic}__{num}" data-ts="{ts}">' 
        f'{article}</article>').encode('utf-8')

class EmitHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        emit(f'Last request from {self.address_string()} {self.requestline} {code} {size} bytes.')

if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite', isolation_level='IMMEDIATE')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    palace_recall('qaczar.py', store=BODY)
    with make_server(HOST, PORT, main_facade, handler_class=EmitHandler) as s:
        emit(f'Facade ready at http://{HOST}:{PORT}/')
        # TODO: Kickstart the first visitor delegate using a crown.
        s.serve_forever(poll_interval=1)


# H.

# TODO: Add a function to extract info from external sources.
# TODO: Add a facade to handle version control (manual reverts).
# TODO: Use a delegate to run tests and publish the production site.

import urllib.request
from contextlib import contextmanager

@contextmanager
def facade_request(*args):
    url = f'http://{HOST}:{PORT}/{"/".join(args)}'
    emit(f'Send request: {url=}')
    try:
        with urllib.request.urlopen(url, timeout=6) as r:
            yield r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        emit(f'HTTPError: {e.code}')

if __name__ == "__main__" and RUNLEVEL == 3:
    DELEGATE = sys.argv[2]
    assert PALACE is None, 'Palace already connected. Not good.'
    PALACE =  sqlite3.connect('file:p.sqlite?mode=ro', uri=True)
    with facade_request('') as r:
        emit(f'Facade response: {r}')
    found = palace_recall('delegate', store=DELEGATE)
    globals()[DELEGATE]()



