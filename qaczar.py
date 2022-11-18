#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import random
import sqlite3
import logging as log
import threading


RUNLEVEL = 0
EPOCH = os.path.getmtime(__file__)

log.basicConfig(stream=sys.stdout)


def sleep_unpredictably(a, b=None):
    time.sleep(random.uniform(a, b or a))
    

def awake_time():
    return int(time.time() - EPOCH)


# --- MIND PALACE ---

us = sqlite3.connect('u.sqlite')


def remember(topic, text):
    with us as c:
        c.execute(
            f'CREATE TABLE IF NOT EXISTS {topic} '
            f'(id INTEGER PRIMARY KEY, ts TEXT, text TEXT)'
        )
        try:
            c.execute(f'INSERT INTO {topic} (ts, text) VALUES (?, ?)', (awake_time(), text))
        except Exception as e:
            log.error(f'Could not remember {topic}: {e}')


def last(table) -> tuple:
    with us:
        try:
            c.execute(f'SELECT id, ts, text FROM {table} ORDER BY id DESC LIMIT 1')
            id, ts, text = us.fetchone()
        except sqlite3.OperationalError:
            log.info(f'No last memory of {table}.')
            return None
    return id, ts, text


def recollect(table, reverse=False, limit=10):
    log.info(f'Recollecting {table}')
    with us as c:
        try:
            r = c.execute(f'SELECT id, ts, text FROM {table} ORDER BY id {"DESC" if reverse else ""} LIMIT {limit}')
        except sqlite3.OperationalError:
            log.info(f'No memory of {table}.')
            return []
        for row in r.fetchall():
            id, ts, text = row
            ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(ts)))
            yield id, ts, text


def enlist_topics():
    with us as c:
        r = c.execute('SELECT name FROM sqlite_master WHERE type="table"')
        return [t[0] for t in r.fetchall()]


def forget(table):
    with us as c:
        c.execute(f'DROP TABLE IF EXISTS {table}')
        log.info(f'Forgot {table}.')


# --- SELF AWARENESS ---

# General functions should be defined before this point if
# they are need to be user by the watcher process.

if __name__ == "__main__":
    log.info('Connecting mind palace.')
    RUNLEVEL = 1
    if len(sys.argv) == 1:
        log.info("Preparing for self awareness fork.")
        import subprocess
        import atexit
        while True:
            server = subprocess.Popen([sys.executable, __file__, "--facade"])
            savepoint = time.time()
            atexit.register(server.terminate)
            mtime = os.path.getmtime(__file__) 
            while True: 
                time.sleep(1)
                if os.path.getmtime(__file__) != mtime:
                    log.info("Mutation detected. Restarting facade.")
                    break
                if server.poll() is not None:  # Server has crashed.
                    log.info("Facade terminated unexpectedly. Reverting self.")
                    original = last('source')
                    if not original:
                        log.info("No self backup found. Terminating.")
                        sys.exit(1)
                    with open(__file__, 'w') as f:
                        f.write(original)
                    break
            log.info("Stopping facade.")
            server.terminate()
            server.wait()


# --- FACADE ELEMENTS ---

def first_visitation():
    global RUNLEVEL
    with open(__file__, 'r') as f:
        remember('source', f.read())
    log.info(f'First visit in {time.time() - EPOCH}s')
    RUNLEVEL = 3


def process_request(request):
    log.info(f'Processing request: {request}')
    return 'Success'


def modulate_facade():
    BASE_CSS = '''
        body { 
            font-family: monospace; 
            background-color: #000; 
            color: #fff; font-size: 12px; 
        }
        table { border-collapse: collapse; }
        td, th { border: 0; font-size: 12px; padding-right: 5px; }
        .left { width: 70%; float: left; }
        .right { width: 30%; float: right; }
        textarea { height: 100px;}
        img { max-width: 100%; }
        th { text-align: left; }
        .todos { list-style: none; padding: 0; }
    '''	
    return BASE_CSS


# --- FACADE INTEGRATION ---

import bottle


@bottle.route('/')
def view_index():
    if RUNLEVEL == 2:
        first_visitation()
    
    loaded = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    active_topic = bottle.request.query.get('t', 'request')
    main_content = list(recollect(active_topic, reverse=True))
    refresh = random.randint(500, 2000)
    topics = enlist_topics()
    awoken =  awake_time()
    css = modulate_facade()

    return bottle.template('''
        <style>{{css}}</style>

        <div class="left">
            <table><tr>
                % for topic in topics:
                    % if topic == active_topic:
                        <th>{{topic}}</th>
                    % else:
                        <th><a href="/?t={{topic}}">{{topic}}</a></th>
                    % end
                % end
            </tr></table><br>
            <table>
                % for id, ts, text in main_content:
                <tr title=""><td>{{! text}}</td></tr>
                % end
            </table>
        </div>
        
        <div class="right">
            <span id="awake"> Awake: {{ awoken }} </span> |
            <span> Loaded: {{ loaded }} </span>
            
            <form action="/api/request" method="post">
                <textarea name="request" rows="10" cols="50"></textarea><br />
                <input type="submit" value="Submit (Ctrl+Enter)" />
            </form>
        </div>    

        <script>
            window.scrollTo(0, document.body.scrollHeight);
            document.querySelector('textarea').addEventListener('keydown', function(e) {
                if (e.keyCode == 13 && e.ctrlKey) {
                    e.preventDefault();
                    document.querySelector('form').submit();
                }
            });
            document.querySelector('textarea').focus();
            setInterval(function() {
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '/api/uptime');
                xhr.onload = function() {
                    if (xhr.status == 200) {
                        if (xhr.responseText < {{ awoken }}) location.reload();
                        else document.querySelector('#awake').innerHTML = 'Uptime: ' + xhr.responseText;
                    }
                };
                xhr.send();
            }, {{ refresh }});
        </script>
    
    ''', **locals())


# Return the server uptime (since the script was last modified).
@bottle.route('/api/uptime')
def api_uptime():
    return str(awake_time())


# Process a request as text and redirect to the main page.
@bottle.route('/api/request', method='POST')
def api_request():
    request = bottle.request.forms.get('request')
    if request:
        remember('request', request.strip())
        result = process_request(request)
        if result:
            remember('result', result, )
            log.info(f'Result: {result}')
    bottle.redirect('/?t=result')


# --- UPKEEP ---

def upkeep_cycle():
    while True:
        # Avoid calling the database, use HTTP API calls instead.
        sleep_unpredictably(60, 120)
        os.system(f'git add . && git commit -m "Upkeep commit" && git push')


HOST = os.environ.get('HOST', 'localhost')
PORT = int(os.environ.get('PORT', 8080))


if __name__ == '__main__':
    RUNLEVEL = 2
    if len(sys.argv) == 2 and sys.argv[1] == '--facade':
        threading.Thread(target=upkeep_cycle).start()
        log.info('Starting facade.')
        bottle.run(host=HOST, port=PORT)
        