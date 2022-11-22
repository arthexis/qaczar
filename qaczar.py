#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A python script that implements observable goal-oriented self-sufficiency.
# It runs every aspect of the web site you are currently visiting.
# The code you are reading is the code that is running at all times.
# H. V. D. C. by Rafa Guillén (arthexis@github) 2022


# TODO: Figure out how to recast the crown from a delegate.
# TODO: Figure out a cool way to do data-entry.
# TODO: Check permissions automatically based on user (consider SSL).
# TODO: Achieve ascension.

import re
import os
import sys
import time
import atexit
import subprocess


SITE = 'QACZAR.COM'
RUNLEVEL = len(sys.argv)
EPOCH = time.time()
DIR = os.path.dirname(__file__)

with open(__file__, 'r', encoding='utf-8') as f:
    BODY = f.read()
assert BODY


# All logging is in this format and redirected to stdout.
def emit(verse):
    print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}:{awakened()}] {verse}')


def awakened():
    return round(time.time() - EPOCH, 4)


def iso8601():
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
    if topic not in TOPICS and store:
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
    elif str.isdigit(fetch):
        r = c.execute(f'SELECT * FROM {topic} WHERE num = {fetch}')
    else:
        r = dynamic_fetch(c, topic, fetch)
    if store is True:
        store = r.fetchone()[2]
    if store is not None: 
        rowid = c.execute(f'INSERT INTO {topic} (ts, artifact) VALUES (?, ?)',
                  (iso8601(), store)).lastrowid
        if fetch == 'new':
            r = c.execute(f'SELECT * FROM {topic} WHERE num = ?', (rowid,))
        emit(f'Stored {topic=} {rowid=} {len(store)=}.')
        PALACE.commit()
    return r.fetchall()
        


def dynamic_fetch(c, topic, fetch):
    raise NotImplementedError(f'Invalid fetch {fetch=}')


# V.

import html
import secrets
import threading
from wsgiref.simple_server import make_server, WSGIRequestHandler

SECRET = secrets.token_hex()
ELEMENTS = {'etome.css': None, 'etome.js': None}

for _elem in ELEMENTS:
    with open(os.path.join(DIR, _elem), 'r', encoding='utf-8') as f:
        ELEMENTS[_elem] = f.read()


class EmitHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        emit(f'Request from {self.address_string()} {self.requestline} {code} {size} bytes.')


def request_facade(environ, respond):
    try:
        layers = [p for p in re.split(r'[/]+', environ['PATH_INFO']) if p]
        depth, status, bodyplan, title = len(layers), '200 OK', None, None
        prelude = visitor_prelude(environ)
        if depth == 0:
            bodyplan = index_facade(environ)
        if depth == 1:
            topic = layers[0]
            artifact = palace_recall(topic, fetch='last')
            title = f'<h3>Latest {topic}</h3>'
            bodyplan = html.escape(artifact[0][2]) if artifact else None
        if depth == 2:
            topic, adapter = layers
            if adapter == '--':
                title = f'<h3>Create {topic}</h3>'
                bodyplan = artifact_form(environ, topic)
                emit(f'Form {topic=} {bodyplan=}.')
        if bodyplan is None:
            status = '404 Not Found'
            bodyplan = f'Not found: {layers=}'
    except Exception as e:
        emit(f'Exceptional request {e}')
        status = '500 Paradox'
        bodyplan = f'<strong><h1>500!</h1> {str(e).title()}</strong>'
    hypertext = hyperlink_text(prelude, title, bodyplan)
    headers = [('Content-type', f'text/html; charset=utf-8')]
    respond(status, headers)
    return [hypertext.encode('utf-8')]


def visitor_prelude(environ):
    visitor = environ['REMOTE_ADDR']
    palace_recall('visitors', store=visitor)
    topics = " ".join(f'[{t}]' for t in TOPICS)
    top = (
        f"Hi <mark>{visitor}</mark>, welcome to "
        f"<h1><a href='/'>{SITE}</a>!</h1> {topics}")
    return top


def index_facade(environ):
    return f"""<p>{SITE} is a <a href="https://en.wikipedia.org/wiki/Quine_(computing)">Quine</a>"""


def hyperlink_text(*artifacts):
    parts = []
    for artifact in artifacts:
        if artifact is None:
            continue      
        if (artifact.startswith('<') and artifact.endswith('>')):
            parts.append(artifact)
            continue
        for topic in TOPICS:
            artifact = re.sub(
                rf'\b{topic}\b', f'<a href="/{topic}">{topic}</a>', artifact)
        indented = re.sub('    ', '&nbsp;&nbsp;&nbsp;&nbsp;', artifact)
        verses = indented.split('\n')
        if len(verses) > 1:
            for i, verse in enumerate(verses):
                if verse.startswith('#'):
                    verses[i] = f'<span class="notes"># {verse[1:]}</span>'
            part = ''.join(f'<li>{verse}</li>' for verse in verses)
        else:
            part = f'<p>{indented}</p>'
        # Put <ol> around parts if there is a <li> in it.
        if '<li>' in part:
            part = f'<ol>{part}</ol>'
        parts.append(part)
    styles, scripts, hr = adapted_styles(), adapted_scripts(), 'hr'
    body = parts[0] if len(parts) == 1 else f'<{hr}>\n'.join(parts)
    return f'<!DOCTYPE html>{styles}<body><main>{body}</main></body>{scripts}</html>'


def adapted_styles():
    return f"""
        <link rel="stylesheet" media="screen" 
            href="https://fontlibrary.org//face/press-start-2p" type="text/css"/> 
        <style>{ELEMENTS['etome.css']}</style>
    """

def adapted_scripts():
    return f"""
        <script>{ELEMENTS['etome.js']}</script>
    """


def watch_elements():
    global ELEMENTS
    elems = {f: os.path.getmtime(f) for f in ELEMENTS.keys()}
    while True:
        for f, mtime in elems.items():
            if os.path.getmtime(f) > mtime:
                with open(f, 'r', encoding='utf-8') as e:
                    ELEMENTS[f] = re.sub(r'\s+', ' ', e.read())
                emit(f'Reloaded {f=}.')
                elems[f] = os.path.getmtime(f)
        time.sleep(2)


def artifact_form(environ, topic):
    method = environ['REQUEST_METHOD']
    if method == 'GET':
        return f"""
            <form action="/{topic}/--" method="post">
                <textarea name="artifact" rows="10" cols="80"></textarea>
                <br><button type="submit">Submit {topic}</button>
            </form>
        """.strip()
    if method == 'POST':
        emit(f'POST {environ=} {topic=}')
        return f"""
            <p>Thanks for submitting {topic}.</p>
            <p><a href="/{topic}">Back to {topic}</a></p>
        """.strip()


# TODO: Add 2 functions to generate and handle forms.


if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    palace_recall('bodyplan', store=BODY)
    threading.Thread(target=watch_elements).start()
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
