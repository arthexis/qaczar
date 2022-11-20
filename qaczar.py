#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A python script that solves the question of life, the universe, and everything.
# H. V. D. C. by Rafa Guillén (arthexis@github) 2022

# My only wish is that humanity maintains qaczar.py until the very end.

# TODO: More testing on the rollback: always write plan to disk at least once.
# TODO: Add visitors with goal-oriented behavior.
# TODO: Achieve ascension.

import os
import sys
import time
import atexit
import sqlite3
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
    emit(f"Created fork {' '.join(args)} {s.pid=}.")
    return s

def watch_over(s):
    while True:
        stable, fragile = True, False
        mtime = os.path.getmtime(__file__)
        while True:
            time.sleep(1)
            if os.path.getmtime(__file__) != mtime:
                emit(f"Mutation detected. Restarting.")  
                with open(__file__, 'r', encoding='utf-8') as f:
                    mutation = f.read()
                mtime = os.path.getmtime(__file__)
                s = create_fork(*s.args, old=s)
                stable = False
                if fragile:
                    create_fork(*s.args, 'recast_crown')  
                continue
            if s.poll() is not None:
                emit(f"Fork died {s.role=} {s.pid=}.")  
                if stable:
                    s = create_fork(s.role, old=s)
                    stable = False
                    continue
                elif not fragile:
                    emit(f"Rolling back to crown's bodyplan.")  
                    fragile = True
                    with open(__file__, 'w', encoding='utf-8') as f:
                        f.write(BODY)
                    continue
                else:
                    emit(f"Rollback failed. Exiting.")  
                    with open(__file__, 'w', encoding='utf-8') as f:
                        f.write(mutation)
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

PALACE = None


def palace_topics():
    c = PALACE.cursor()
    r = c.execute('SELECT name FROM sqlite_master WHERE type="table"')
    return [t[0] for t in r.fetchall()]

def palace_recall(topic, artifact=None):
    # Put basically all the SQL stuff in one function and get over it.
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
        PALACE.commit()
    c.close()
    emit(f'Recalled {num=} {topic=} {artifact=} {last=}')
    return last[0] if last else None


# TODO: Add a function to manage relationships between artifacts.


# V.

from wsgiref.simple_server import make_server, WSGIRequestHandler


class EmitHandler(WSGIRequestHandler):
    def log_request(self, code='-', size='-'):
        pass

def request_facade(environ, start_response):
    path = environ['PATH_INFO']
    layers = path[1:].split('/', 1) if '/' in path else (path[1:], None)
    emit(f'Facade request: {layers=}')
    if layers == ['']:
        bodyplan = default_facade()
    else:
        bodyplan = palace_recall(*layers)
    headers = [('Content-type', 'text/html; charset=utf-8')]
    start_response('200 OK', headers)
    return [bodyplan.encode('utf-8')]

def default_facade():
    return "Welcome."


if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite')
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    with make_server(HOST, PORT, request_facade, handler_class=EmitHandler) as s:
        emit(f'Facade ready at http://{HOST}:{PORT}/')
        s.serve_forever(poll_interval=1)


# H.

import urllib.request
from contextlib import contextmanager


@contextmanager
def facade_request(request):
    # Being optimistic that http still works in 98,472 C.E.
    with urllib.request.urlopen(f'http://{HOST}:{PORT}/{request}') as r:
        yield r.read().decode('utf-8')


def recast_crown():
    emit(f'Recasting crown.')
    with facade_request('lineage') as bodyplan:
        with open(__file__, 'w', encoding='utf-8') as f:
            f.write(bodyplan)
    emit(f'Recast complete.')


if __name__ == "__main__" and RUNLEVEL == 3:
    GEASS = sys.argv[2]
    with facade_request('') as r:
        emit(f'Check crown {r.status=}')
    globals()[GEASS]()
