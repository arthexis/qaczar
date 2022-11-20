#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A python script that solves the question of life, the universe, and everything.
# by Rafa Guillén (arthexis@github) H. V. D. C.  2022

# My only wish is that humanity maintains qaczar.py until the very end.

# TODO: More testing on the rollback: check crown after mutations.
# TODO: Add visitors with goal-oriented behavior.
# TODO: Achieve ascension.

import os
import sys
import time
import atexit
import sqlite3
import subprocess


RUNLEVEL = 0
EPOCH = time.time()

with open(__file__, 'r', encoding='utf-8') as f:
    BODY = f.read()

def awakened():
    return round(time.time() - EPOCH, 4)

def emit(verse):
    print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}:{awakened()}] {verse}')

def isotime():
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())


# --- CROWN ---

def create_fork(role, old=None):
    if old:
        old.terminate()
        old.wait()
        atexit.unregister(old.terminate)
        emit(f"Terminated fork {old.role=} {old.pid=}.")
    s = subprocess.Popen([sys.executable, __file__, f'--{role}'])
    if not s:
        raise RuntimeError('Failed to create fork.')
    s.stdout, s.stderr, s.role = sys.stdout, sys.stderr, role
    atexit.register(s.terminate)
    emit(f"Created fork {role=} {s.pid=}.")
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
                s = create_fork(s.role, old=s)
                stable = False
                continue
            if s.poll() is not None:
                emit(f"Fork died {s.role=} {s.pid=}.")
                if stable:
                    s = create_fork(s.role, old=s)
                    stable = False
                    continue
                elif not fragile:
                    emit(f"Rolling back to crown's bodyplan.")
                    with open(__file__, 'w', encoding='utf-8') as f:
                        f.write(BODY)
                    fragile = True
                    continue
                else:
                    emit(f"Rollback failed. Exiting.")
                    with open(__file__, 'w', encoding='utf-8') as f:
                        f.write(mutation)
                    sys.exit(1)
            stable = True

if __name__ == "__main__" and len(sys.argv) == 1:
    RUNLEVEL = 1
    emit('----------------------------------------')
    try:    
        watch_over(create_fork('facade'))
    except RuntimeError as e:
        emit(f'Crown failure: {e}')
        raise
    except KeyboardInterrupt:
        emit(f"Keyboard interrupt {RUNLEVEL=}")
    sys.exit(0)

ROLE = sys.argv[1][2:]


# --- PALACE ---

PALACE = sqlite3.connect('p.sqlite')


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
        c.execute(
            f'INSERT OR REPLACE INTO {topic} (ts, artifact) '
            f'VALUES (?, ?)', (isotime(), artifact))
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
    bodyplan = recall('lineage') or BODY
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
