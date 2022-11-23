#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that implements observable goal-oriented self-sufficiency.
# It runs every aspect of the web site you are currently visiting.
# The code you are reading is the code that is running at all times.
# If your computer has Python, you can copy and paste this code into a file
# and have your own 100% self-managed site running in seconds.

# H. V. D. C. by Rafa Guillén (arthexis@github) 2022

# TODO:  HTML Template.
# TODO:  Load all the "element files" into the database. 



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

def fread(fn):
    try: 
        with open(fn, 'r', encoding='utf-8') as f: return f.read()
    except FileNotFoundError: return None 

assert (BODY := fread(__file__)), 'Bodyplan not found.'


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

def watch_over(s):  # Aka. The Crown
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
import sqlite3

PALACE = None
TOPICS = []

def summary(text):
    return re.sub(r'\s+', ' ', text)[:30] if text else 'N/A'

def palace_recall(topic, /, fetch=True, store=None):  
    global PALACE, TOPICS
    topic = topic.lower().replace('.', '__')
    assert store in (None, True) or isinstance(store, str), f'Invalid recall {store=}'
    assert (topic and re.match(r'^[a-zA-Z0-9_\-]+$', topic)  # Don't allow underscore
        and len(topic) < 40 and not topic.startswith('sqlite_')), f'Invalid recall {topic=}'
    short = f'"{summary(store)}" ({len(store)})' if store else 'N/A'
    emit(f'Recall {topic=} {fetch=} {short=}.')
    c = PALACE.cursor()
    if not TOPICS:
        c.execute('SELECT name FROM sqlite_master WHERE type="table" AND name not LIKE "sqlite_%"')
        TOPICS.extend(t[0] for t in c.fetchall())
    if topic not in TOPICS:
        c.execute(f'CREATE TABLE IF NOT EXISTS {topic} ('
            f'num INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, article TEXT)')
        if seed := fread(f'{DIR}/seeds/{topic.replace("__", ".")}'):
            c.execute(f'INSERT INTO {topic} (ts, article) VALUES (?, ?)', (isotime(), seed))
            PALACE.commit()
        TOPICS.append(topic)
    if fetch:
        found = c.execute(f'SELECT num, ts, article FROM {topic} ORDER BY ts DESC LIMIT 1') 
    if store is True:  # Check for True because store can be a string.
        store = r.fetchone()[2]
    if store is not None: 
        rowid = c.execute(
            f'INSERT INTO {topic} (ts, article) VALUES (?, ?)', (isotime(), store)).lastrowid
        PALACE.commit()
        emit(f'Committed {topic=} {rowid=} {short=}.')
    if (found := found.fetchone() if fetch and found else None):
        return topic, found[0], found[1], found[2]


# V.

from wsgiref.simple_server import make_server, WSGIRequestHandler

IGNORE = ('favicon.ico', )

# Main entrypoint for the WSGI server.
def main_facade(env, respond):
    try:
        layers = [p for p in re.split(r'[/]+', env['PATH_INFO']) if p]
        status = '404 Not Found' if layers and layers[0] in IGNORE else '200 OK'
        respond(status, [('Content-type', f'text/html; charset=utf-8')])
        if css := hypertext(palace_recall('qaczar.css')): yield css
        for layer in layers:
            if article := palace_recall(layer):
                yield hypertext(article)
        if js := hypertext(palace_recall('qaczar.js')): yield js
    except Exception as e:
        emit(f'Facade error: {e} {env=}')

def hypertext(article):
    if not article: return b' '
    topic, num, ts, article = article
    if topic.endswith('__css'):
        return f'<style>{article}</style>'.encode('utf-8')
    return f'<article id="{topic}__{num}" data-ts="{ts}">{article}</article>'.encode('utf-8')

class EmitHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        emit(f'Request from {self.address_string()} {self.requestline} {code} {size} bytes.')

if __name__ == "__main__" and RUNLEVEL == 2:
    # TODO: Test with IMMEDIATE isolation_level (default is DEFERRED).
    PALACE =  sqlite3.connect('p.sqlite')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    with make_server(HOST, PORT, main_facade, handler_class=EmitHandler) as s:
        emit(f'Facade ready at http://{HOST}:{PORT}/')
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



