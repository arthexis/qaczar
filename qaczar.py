#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A python script that implements observable goal-oriented self-sufficiency.
# H. V. D. C. by Rafa Guillén (arthexis@github) 2022


# TODO: More testing on the rollback: always write plan to disk at least once.
# TODO: Add visitors with goal-oriented behavior.
# TODO: Achieve ascension.

import re
import os
import sys
import time
import atexit
import subprocess


QACZAR = 'QACZAR'
RUNLEVEL = len(sys.argv)
EPOCH = time.time()

with open(__file__, 'r', encoding='utf-8') as f:
    BODY = f.read()
assert BODY


def emit(verse):
    # All logging is in this format and redirected to stdout.
    print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}:{awakened()}] {verse}')


def awakened():
    return round(time.time() - EPOCH, 4)


def isotime():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())


# C.

HOST, PORT = 'localhost', 5000

def create_fork(*args, old=None):
    assert len(args) > 0
    if old is not None:
        old.terminate()
        old.wait()
        atexit.unregister(old.terminate)
    s = subprocess.Popen([sys.executable, __file__, *[str(a) for a in args]])
    if not s:
        raise RuntimeError('Failed to create fork.')
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"Created fork {' '.join(str(a) for a in args)} {s.pid=}.")
    return s


def watch_over(s):
    while True:
        stable, mtime = True, os.path.getmtime(__file__)
        while True:
            time.sleep(1)
            if os.path.getmtime(__file__) != mtime:
                with open(__file__, 'r', encoding='utf-8') as f:
                    mutation = f.read()
                mtime = os.path.getmtime(__file__)
                if mutation != BODY:
                    emit(f"Mutation {len(mutation)=} {len(BODY)=}. Restarting.")
                    stable = False
                    s = create_fork(*s.args, old=s)
                continue
            if s.poll() is not None:
                emit(f"Fork died {s.args=} {s.pid=}.")  
                if stable:
                    s = create_fork(*s.args, old=s)
                    stable = False
                    continue
                else:
                    emit("Crown unstable. Aborting.")
                    sys.exit(1)
            stable = True


if __name__ == "__main__" and RUNLEVEL == 1:
    emit('----------------------------------------')
    try:    
        watch_over(create_fork(f'{HOST}:{PORT}'))
    except RuntimeError as e:
        emit(f'Crown failure: {e}')
        raise
    except KeyboardInterrupt:
        emit(f"Keyboard interrupt {RUNLEVEL=}")
    sys.exit(0)


# D.

import sqlite3

PALACE = None
TOPICS = []


def summarized(text):
    return re.sub(r'\s+', ' ', text)[:40] if text else 'N/A'


def palace_recall(topic, /, fetch='last', store=None):
    assert store in (None, True) or isinstance(store, str), f'Invalid recall {store=}'
    assert (topic and re.match(r'^[a-zA-Z0-9_\-]+$', topic) 
        and len(topic) < 40 and not topic.startswith('sqlite_')), f'Invalid recall {topic=}'
    emit(f'Recall {topic=} {fetch=} {summarized(store)=}.')
    c = PALACE.cursor()
    if not TOPICS:
        c.execute('SELECT name FROM sqlite_master WHERE type="table" AND name not LIKE "sqlite_%"')
        TOPICS.extend(t[0] for t in c.fetchall())
    if topic not in TOPICS:
        c.execute(
            f'CREATE TABLE IF NOT EXISTS {topic} ('
            f'num INTEGER PRIMARY KEY AUTOINCREMENT, '
            f'ts TEXT, artifact TEXT)')
        emit(f'Created {topic=}.')
        TOPICS.append(topic)
    if fetch in ('last', 'first'):
        r = c.execute(f'SELECT * FROM {topic} ORDER BY ts {"DESC" if fetch == "last" else "ASC"} LIMIT 1')
    elif fetch == 'random':
        r = c.execute(f'SELECT * FROM {topic} ORDER BY RANDOM() LIMIT 1')
    elif fetch == 'new':
        pass
    else:
        r = dynamic_fetch(c, topic, fetch)
    if store is True:
        store = r.fetchone()[2]
    if store is not None: 
        rowid = c.execute(f'INSERT INTO {topic} (ts, artifact) VALUES (?, ?)',
                  (isotime(), store)).lastrowid
        if fetch == 'new':
            r = c.execute(f'SELECT * FROM {topic} WHERE num = ?', (rowid,))
        emit(f'Stored {topic=} {rowid=} {len(store)=}.')
        PALACE.commit()
    return r.fetchall()


def dynamic_fetch(c, topic, fetch):
    raise NotImplementedError(f'Invalid fetch {fetch=}')


# V.

import secrets
from wsgiref.simple_server import make_server, WSGIRequestHandler

SECRET = secrets.token_hex()

with open('etome.css', 'r', encoding='utf-8') as f:
    STYLE = re.sub(r'\s+', ' ', f.read())


class EmitHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        emit(f'Request from {self.address_string()} {self.requestline} {code} {size} bytes.')


def request_facade(environ, respond):
    layers = [p for p in re.split(r'[/]+', environ['PATH_INFO']) if p]
    depth, status, bodyplan = len(layers), '200 OK', None
    prelude = visitor_prelude(environ)
    if depth >= 1:
        topic = layers[0]
        artifact = palace_recall(topic)
        bodyplan = artifact[0][2] if artifact else None
    if bodyplan is None:
        status = '404 Not Found'
        bodyplan = f'Not found: {layers=}'
    hypertext = hyperlink_text(prelude, bodyplan)
    headers = [('Content-type', f'text/html; charset=utf-8')]
    respond(status, headers)
    return [hypertext.encode('utf-8')]


def visitor_prelude(environ):
    visitor = environ['REMOTE_ADDR']
    palace_recall('visitors', store=visitor)
    topics = " ".join(f'[{t}]' for t in TOPICS)
    top = f"Hi {visitor}, welcome to QACZAR.\n\tTopics: {topics}"
    return top


def delegation_facade(environ, delegate):
    s = create_fork(f'{HOST}:{PORT}', delegate)
    emit(f"Delegate {s.pid=} {delegate=}")
    watch_over(s)


def hyperlink_text(*artifacts):
    parts = []
    for artifact in artifacts:
        for topic in TOPICS:
            artifact = re.sub(
                rf'\b{topic}\b', f'<a href="/{topic}">{topic}</a>', artifact)
        indented = re.sub('    ', '&nbsp;&nbsp;&nbsp;&nbsp;', artifact)
        verses = indented.split('\n')
        for i, verse in enumerate(verses):
            if verse.startswith('#'):
                verses[i] = f'<span class="notes"># {verse[1:]}</span>'
        part = '\n'.join(f'<li>{verse}\n</li>' for verse in verses)
        parts.append(part)
    style = adapted_style()
    body = parts[0] if len(parts) == 1 else '<hr>\n'.join(parts)
    hypertext = f'<!DOCTYPE html>{style}<body><ol>{body}</ol></body></html>'
    return hypertext


def adapted_style():
    return f"""
        <link rel="stylesheet" media="screen" 
            href="https://fontlibrary.org//face/press-start-2p" type="text/css"/> 
        <style>{STYLE}</style>
    """


# TODO: Add 2 functions to generate and handle forms.


if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    palace_recall('bodyplan', store=BODY)
    with make_server(HOST, PORT, request_facade, handler_class=EmitHandler) as s:
        emit(f'Facade ready at http://{HOST}:{PORT}/')
        s.serve_forever(poll_interval=1)


# H.

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


# TODO: Add a function to extract info from external sources.
# TODO: Add a function to handle version control? Or add it to recast_crown?


if __name__ == "__main__" and RUNLEVEL == 3:
    DELEGATE = sys.argv[2]
    PALACE =  sqlite3.connect('file:p.sqlite?mode=ro', uri=True)
    with facade_request('') as r:
        emit(f'Facade response: {r}')
    found = palace_recall('delegate', store=DELEGATE)
    globals()[DELEGATE]()
