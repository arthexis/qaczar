#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A python script that calculates the entire fibbonacci sequence.
# H. V. D. C. by Rafa Guillén (arthexis@github) 2022

# My only wish is that humanity maintains qaczar.py until the very end.

# TODO: More testing on the rollback: always write plan to disk at least once.
# TODO: Add visitors with goal-oriented behavior.
# TODO: Achieve ascension.

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
    if old:
        old.terminate()
        old.wait()
        atexit.unregister(old.terminate)
        emit(f"Terminated fork {old.args=} {old.pid=}.")
    s = subprocess.Popen([sys.executable, __file__, *[str(a) for a in args]])
    if not s:
        raise RuntimeError('Failed to create fork.')
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"Created fork {' '.join(str(a) for a in args)} {s.pid=}.")
    return s

def watch_over(s):
    while True:
        stable, fragile = True, False
        mtime = os.path.getmtime(__file__)
        while True:
            time.sleep(1)
            if os.path.getmtime(__file__) != mtime:
                emit(f"Mutation detected. Compare to BODY.")
                with open(__file__, 'r', encoding='utf-8') as f:
                    mutation = f.read()
                mtime = os.path.getmtime(__file__)
                if mutation != BODY:
                    emit(f"Mutation confirmed. Restarting.")
                    s = create_fork(*s.args, old=s)
                    stable = False
                if fragile:
                    create_fork(*s.args, 'recast_crown')  
                continue
            if s.poll() is not None:
                emit(f"Fork died {s.args=} {s.pid=}.")  
                if stable:
                    s = create_fork(*s.args, old=s)
                    stable = False
                    continue
                elif not fragile:
                    emit(f"Rolling back to crown's bodyplan.")  
                    fragile = True
                    with open(__file__, 'w', encoding='utf-8') as f:
                        f.write(BODY)
                    continue
                elif fragile:
                    emit(f"Rollback failed. Reverting.")  
                    with open(__file__, 'w', encoding='utf-8') as f:
                        f.write(mutation)
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

def palace_topics():
    c = PALACE.cursor()
    r = c.execute('SELECT name FROM sqlite_master WHERE type="table"')
    return [t[0] for t in r.fetchall()]

def palace_recall(topic, artifact=None, forget=False):
    assert topic, 'Topic must be specified.'
    c = PALACE.cursor()
    if topic not in palace_topics():
        c.execute(
            f'CREATE TABLE IF NOT EXISTS {topic} ('
            f'num INTEGER PRIMARY KEY AUTOINCREMENT, '
            f'ts TEXT, artifact TEXT)')
    last = c.execute(
        f'SELECT num, artifact FROM {topic} '
        f'ORDER BY ts DESC LIMIT 1').fetchone()
    num = None if last is None else last[0]
    if artifact:
        num = c.execute(
            f'SELECT num FROM {topic} '
            f'WHERE artifact=?', (artifact,)).fetchone()
        if num:
            num = num[0]
            c.execute(
                f'UPDATE {topic} SET ts=? WHERE num=?',
                (isotime(), num))
        else:
            c.execute(
                f'INSERT INTO {topic} (ts, artifact) VALUES (?, ?)',
                (isotime(), artifact)).lastrowid
        if forget:
            c.execute(f'DELETE FROM {topic} WHERE num=?', (num,))
    elif forget:
        c.execute(f'DROP TABLE {topic}')
    PALACE.commit()
    c.close()
    emit(f'Recalled {num=} {topic=}')
    return last[1] if last else None


# TODO: Add a function to manage relationships between artifacts.


# V.

from wsgiref.simple_server import make_server, WSGIRequestHandler


class EmitHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        pass


def request_facade(environ, start_response):
    pi = environ['PATH_INFO']
    layers = pi[1:].split('/', 1) if '/' in pi else (pi[1:], None)
    emit(f'Facade request: {layers=}')
    headers = [('Content-type', 'text/html; charset=utf-8')]
    bodyplan = None
    if layers == ['']:
        bodyplan = default_facade()
    elif len(layers) == 1:
        bodyplan = palace_recall(layers[0])
    else:
        emit(f'Invalid request: {layers=}')
    if bodyplan is None:
        emit(f'No bodyplan found for {layers=}')
        start_response('404 Not Found', headers)
        return [f'Not Found: {layers=}'.encode('utf-8')]
    start_response('200 OK', headers)
    return [format_html(bodyplan)]


def format_html(soup):
    soup = soup.replace('\r\n', '<br>').replace('\n', '<br>')
    return f'''<!DOCTYPE html>
        <html><head>
        <meta charset="utf-8">
        <title>{soup[:20]}</title>
        </head><body>
        <pre>{soup}</pre>
        </body></html>'''.encode('utf-8')


def default_facade():
    # <!--
    return str(palace_topics())
    # -->

# TODO: Add 2 functions to generate and handle forms.


if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    palace_recall('lineage', BODY)
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
    with urllib.request.urlopen(url) as r:
        yield r.read().decode('utf-8')


def recast_crown():
    emit(f'Recasting crown.')
    with facade_request('lineage') as bodyplan:
        with open(__file__, 'w', encoding='utf-8') as f:
            f.write(bodyplan)
    emit(f'Recast complete.')


# TODO: Add a function to extract info from external sources.
# TODO: Add a function to handle version control? Or add it to recast_crown?


if __name__ == "__main__" and RUNLEVEL == 3:
    GEASS = sys.argv[2]
    PALACE =  sqlite3.connect('file:p.sqlite?mode=ro', uri=True)
    with facade_request('') as r:
        emit(f'Facade response: {r}')
    globals()[GEASS]()
