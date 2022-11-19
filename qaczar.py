#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A python script that solves the question of life, the universe, and everything.
# by Rafa Guillén (arthexis@github) H. V. D. C.  2022
# My only wish is that humanity maintains qaczar.py until the very end.

# TODO: Simplify the Facade by using WSGI Ref. Emit logging.
# TODO: Achieve ascension.

# --- WATCHTOWER ---

import os
import sys
import time
import random
import sqlite3
import subprocess


RUNLEVEL = 0
HEARTBEAT = 1.0
EPOCH = int(os.path.getmtime(__file__))
PATH = os.path.dirname(__file__)

random.seed(137)


def awakened():
    return round(time.time() - EPOCH, 4)


def emit(message):
    line = sys._getframe(1).f_lineno
    caller = sys._getframe(1).f_code.co_name
    print(f'[{RUNLEVEL}:{line}] +{awakened()} {caller}: {message}')


emit('----------------------------------------')


# --- CROWN ---


def current_source():
    with open(__file__, 'r') as f:
        source = f.read()
    if not source:
        emit('Current source code is empty.')
    else:
        emit(f'Read {len(source)} bytes from file.')
    return source


def cast_successor():
    us = sqlite3.connect('u.sqlite')
    with us as c:
        try:
            r = c.execute(f'SELECT id, text FROM source ORDER BY id DESC LIMIT 1')
            next, source = r.fetchone()
            emit(f'Next available source is #{next}.')
        except Exception as e:
            emit(f'Could not cast successor: {e}')
            sys.exit(42)
        c.execute(f'DELETE FROM source WHERE id = {next}')
    us.close()


def heartbeat():
    return HEARTBEAT * (RUNLEVEL + 1)


if __name__ == "__main__":
    assert RUNLEVEL == 0, f"[{RUNLEVEL}!=0] Causality violation."
    RUNLEVEL = 1
    if len(sys.argv) == 1:
        emit("Prepping the crown.")  # H.
        import atexit
        while True:
            server = subprocess.Popen([sys.executable, __file__, "--f"]) # V.
            server.stdout = sys.stdout
            emit("Facade subprocess started.")
            atexit.register(server.terminate)
            mtime = os.path.getmtime(__file__) 
            while True: 
                time.sleep(heartbeat())
                if os.path.getmtime(__file__) != mtime:
                    emit("Mutation detected. Restarting facade.") # D.
                    break
                if server.poll() is not None: 
                    emit("Unexpected termination. Regenerating.") # C.
                    cast_successor()
                    break


# --- PALACE ---

emit(f'Connecting palace (u.sqlite).')
us = sqlite3.connect('u.sqlite')


def remember(topic, text):
    emit(f'Remember <{topic}> ({len(text)} bytes).')
    with us as c:
        c.execute(
            f'CREATE TABLE IF NOT EXISTS {topic} '
            f'(id INTEGER PRIMARY KEY, ts TEXT, text TEXT)'
        )
        try:
            # Get the id that was inserted.
            r = c.execute(
                f'INSERT INTO {topic} (ts, text) VALUES (?, ?)',
                (awakened(), text)
            )
            _id = r.lastrowid
            emit(f"Memory created <{topic}> #{_id}.")
            return _id
        except sqlite3.OperationalError as e:
            emit(f'Lost in palace: {e}')
        except Exception as e:
            emit(f'Could not remember <{topic}>: {e}')


def last(table) -> tuple:
    with us as c:
        try:
            r = c.execute(f'SELECT id, text FROM {table} ORDER BY id DESC LIMIT 1')
            id, text = r.fetchone()
        except sqlite3.OperationalError:
            emit(f'No last memory of {table}.')
            return None, ''
    return id, text


def recollect(table, reverse=False, limit=10):
    emit(f'Recollecting {table}')
    with us as c:
        try:
            r = c.execute(
                f'SELECT id, ts, text FROM {table} ORDER BY id '
                f'{"DESC" if reverse else ""} LIMIT {limit}')
        except sqlite3.OperationalError:
            emit(f'No memory of {table}.')
            return []
        for row in r.fetchall():
            id, ts, text = row
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(ts)))
            yield id, ts, text


def enlist_topics():
    with us as c:
        r = c.execute('SELECT name FROM sqlite_master WHERE type="table"')
        return [t[0] for t in r.fetchall()]


def forget(topic):
    # Remove the last entry of a topic if there is one.
    with us as c:
        try:
            r = c.execute(f'SELECT id FROM {topic} ORDER BY id DESC LIMIT 1')
            _id = r.fetchone()[0]
            c.execute(f'DELETE FROM {topic} WHERE id = {_id}')
            emit(f'Forgotten <{topic}> #{_id}.')
        except sqlite3.OperationalError:
            emit(f'No memory of {topic}.')
        except Exception as e:
            emit(f'Could not forget <{topic}>: {e}')
        try:
            r = c.execute(f'SELECT COUNT(*) FROM {topic}')
            count = r.fetchone()[0]
            if count == 0:
                c.execute(f'DROP TABLE {topic}')
                emit(f'Dropped <{topic}>.')
        except sqlite3.OperationalError:
            pass


def update_backups():
    emit('Update backups.')
    source = current_source()
    if last('source')[1] == source:
        emit('Nothing to backup. Skipping.')
    else:
        _id = remember('source', source)
        emit('Git commit.')
        subprocess.run(['git', 'add', 'u.sqlite', __file__])
        subprocess.run(['git', 'commit', '-m', f'Backup <source> #{_id}'])
        subprocess.run(['git', 'push'])
        emit(f'Git push complete <source> #{_id}.')


# --- FACADE ---

HOST = os.environ.get('HOST', 'localhost')
PORT = int(os.environ.get('PORT', 8080))

def facade_app(environ, start_response):
    source = last('source')[1]
    body = f'''
        <!DOCTYPE html>
        <meta http-equiv="refresh" content="{heartbeat()}">
        <title>QACZAR</title>
        <pre>{source}</pre>
    '''.encode('utf-8')
    status = '200 OK'
    headers = [('Content-type', 'text/html; charset=utf-8')]
    start_response(status, headers)
    return [body]


if __name__ == '__main__':
    assert RUNLEVEL == 1, f"[{RUNLEVEL}!=1] Causality violation."
    update_backups()
    if len(sys.argv) == 2 and sys.argv[1] == '--f':
        RUNLEVEL = 2
        from wsgiref.simple_server import make_server, WSGIRequestHandler

        class Unhandler(WSGIRequestHandler):
            def log_request(self, format, *args):
                pass

        with make_server(HOST, PORT, facade_app, handler_class=Unhandler) as facade:
            emit(f'Serving on {HOST}:{PORT}')
            facade.serve_forever()
