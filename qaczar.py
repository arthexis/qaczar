#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A python script that solves the question of life, the universe, and everything.
# by Rafa Guillén (arthexis@github) H. V. D. C.  2022

# My only wish is that humanity maintains qaczar.py until the very end.

# TODO: Add visitors with goal-oriented behavior.
# TODO: More testing on the rollback mechanism.
# TODO: Achieve ascension.

import os
import sys
import time
import atexit
import sqlite3
import subprocess


RUNLEVEL = 0
EPOCH = time.time()

def awakened():
    return round(time.time() - EPOCH, 4)

def emit(verse):
    print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}:{awakened()}] {verse}')


# --- CROWN ---

def create_fork(role):
    try:
        with sqlite3.connect('p.sqlite') as p:
            num, bodyplan = p.cursor().execute(
                f'SELECT num, artifact FROM lineage '
                f'ORDER BY ts DESC LIMIT 1').fetchone()
            emit(f'Recalled bodyplan from <lineage#{num}>.')
            with open(__file__, 'w', encoding='utf-8') as f:
                f.write(bodyplan)
    except Exception as e:
        emit('Using bodyplan on disk.')
    s = subprocess.Popen([sys.executable, __file__, f'--{role}'])
    s.role = role 
    s.stdout, s.stderr = sys.stdout, sys.stderr
    atexit.register(s.terminate)
    emit(f"Created fork {role=} {s.pid=}.")
    return s

def watch_forever(s):
    stable = True
    mtime = os.path.getmtime(__file__)
    while True:
        time.sleep(1)
        if os.path.getmtime(__file__) != mtime:
            if not stable:
                emit('Crown unstable. Terminating.')
                sys.exit(1)
            emit(f"Mutation detected. Switch to successor.")
            stable = False
            s.terminate()
            s.wait()
            atexit.unregister(s.terminate)
            mtime = os.path.getmtime(__file__)
            s = create_fork(s.role)
            continue
        if s.poll() is not None:
            return emit(f"Fork died {s.role=} {s.pid=}.")
        stable = True

if __name__ == "__main__" and len(sys.argv) == 1:
    RUNLEVEL = 1
    try:    
        while True:
            emit('----------------------------------------')
            s = create_fork('facade')
            if not s:
                raise RuntimeError('Failed to create fork.')
            watch_forever(s)
            atexit.unregister(s.terminate)
    except RuntimeError as e:
        emit(f'Crown failure: {e}')
    except KeyboardInterrupt:
        emit(f"Keyboard interrupt {RUNLEVEL=}")
    finally:
        sys.exit(0)

ROLE = sys.argv[1][2:]


# --- PALACE ---

PALACE = sqlite3.connect('p.sqlite')

with open(__file__, 'r', encoding='utf-8') as f:
    BODY = f.read()


def topics():
    c = PALACE.cursor()
    r = c.execute('SELECT name FROM sqlite_master WHERE type="table"')
    return [t[0] for t in r.fetchall()]

def recall(topic, artifact=None):
    emit(f'Recall {topic=} {artifact=}')
    c = PALACE.cursor()
    if topic not in topics():
        c.execute(
            f'CREATE TABLE IF NOT EXISTS {topic} ('
            f'num INTEGER PRIMARY KEY AUTOINCREMENT, '
            f'ts TEXT, artifact TEXT)')
    latest = c.execute(
        f'SELECT artifact FROM {topic} '
        f'ORDER BY ts DESC LIMIT 1').fetchone()
    if artifact:
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())
        c.execute(
            f'INSERT OR REPLACE INTO {topic} (ts, artifact) '
            f'VALUES (?, ?)', (ts, artifact))
        PALACE.commit()
    c.close()
    return latest[0] if latest else None
    

# --- FACADE ---

from wsgiref.simple_server import make_server, WSGIRequestHandler

class Unhandler(WSGIRequestHandler):
    def log_request(self, format, *args):
        pass

def visitor_facade(environ, start_response):
    intent = environ['PATH_INFO']
    emit(f'Facade request: {intent}')
    headers = [('Content-type', 'text/html; charset=utf-8')]
    start_response('200 OK', headers)
    bodyplan = recall('lineage', BODY) or BODY
    # <!--
    document = f'''
        <meta http-equiv="refresh" content="60">
        <title>{ROLE} {awakened()}</title><pre>{bodyplan}</pre>
    '''
    # -->
    return [document.encode('utf-8')]


if __name__ == "__main__" and ROLE == 'facade':
    RUNLEVEL = 2
    with make_server('localhost', 5000, visitor_facade, handler_class=Unhandler) as s:
        emit(f'Facade ready at http://localhost:5000/')
        s.serve_forever(poll_interval=1)
