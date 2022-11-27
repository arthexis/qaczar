#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that does everything by itself.
# H. V. D. C. by Rafa Guillén (arthexis@gmail.com) 2022-2023

# Coding recommendations:

# 1. Keep the line width to less than 100 characters.
# 2. Use functions, not classes, for modularity, composability and encapsulation.
# 3. Functions should not reference functions or globals from later in the script.


import os
import sys
import time
import atexit
import subprocess

# We don't import everything at the start to keep the runtime of 
# the crown (watcher) as simple as possible. Later we can import more modules.

# TODO: Python Source Query Language
#       -> an easier way to inspect the source code of a Python module as text.

# This is the name that will appear on the title of the website.
SITE = 'qaczar.com'
BRANCH = 'main'

RUNLEVEL = len(sys.argv)
DIR = os.path.dirname(__file__)


# These utility functions are used everywhere, be careful when changing them.

def isotime(t=None): 
    return time.strftime('%Y-%m-%d %H:%M:%S', t or time.gmtime())

def emit(verse): 
     print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}] [{isotime()}] {verse}')

def fread(fn, decode=None):
    try: 
        with open(fn, 'r' if decode else 'rb', encoding=decode) as f:  
            return f.read()
    except FileNotFoundError: 
        return None 

SOURCE = fread(__file__, decode='utf-8')


# C.

HOST, PORT = os.environ.get('HOSTNAME', 'localhost'), 8080 

# Creates a running copy of ourselves with different arguments.
# If an old process is provided, it will be terminated gently first.
# This keeps the crown stable, since it never has to deal with a dead fork.
def create_fork(*args, old=None):
    assert len(args) > 0, 'No args provided to create_fork.'
    if old is not None:
        old.terminate(); old.wait()
        atexit.unregister(old.terminate)
    s = subprocess.Popen([sys.executable, __file__, *[str(a) for a in args]])
    if not s:
        raise RuntimeError('Failed to create fork.')
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"Created fork {' '.join(str(a) for a in args)} {s.pid=}.")
    return s

# aka. The Crown
# Watch over s to ensure it never dies. If it does, create a new one.
# If the source changes, kill s and start a new one with the same params.
# If the new copy fails, abort and investigate the error.
def watch_over(s):  
    global SOURCE
    while True:
        stable, mtime = True, os.path.getmtime(__file__)
        while True:
            time.sleep(2.6)  # A reasonable time for take backs.
            if os.path.getmtime(__file__) != mtime:
                mutation, mtime = fread(__file__), os.path.getmtime(__file__)
                if mutation != SOURCE:
                    emit(f"Mutation detected {len(mutation)=} {len(SOURCE)=}. Restarting.")
                    s, stable = create_fork(*s.args, old=s), False
                continue
            if s.poll() is not None:
                if stable:
                    emit(f"Fork died {s.args=} {s.pid=}. Restarting.")
                    s, stable = create_fork(*s.args, old=s), False
                    continue
                emit("Crown unstable, aborting. Check qaczar.py for errors.")
                sys.exit(1)
            stable = True

# RUNLEVEL will only be greater than 0 when qaczar.py is executing.
# (ie. not when it is being imported by another script).
# Each subsequent runlevel represents a deeper level of fork recursion.
if __name__ == "__main__" and RUNLEVEL == 1:
    emit('----------------------------------------')
    try:    
        # We copy ourselves and put the crown on the copy.
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
import collections

# This global will hold the database connection.
# Instead of using it directly, use palace_store() and palace_fetch().
# If you need a direct access cursor, get one with palace_cursor().
PALACE = None

# Map of known topics to their content types.
# This map is always acurrate at RUNLEVEL 2, but not above.
TOPICS = {}

# These are generic functions that can be used to manipulate arbitrary
# text and files, and are useful for interacting with palace data.

def seed_mtime(topic, old_mtime=0):
    global DIR
    try:
        path = f'{DIR}/seeds/{topic.replace("__", ".")}'
        new_mtime = int(os.path.getmtime(path))
        if new_mtime > old_mtime: return new_mtime, fread(path)
        else: return old_mtime, None
    except FileNotFoundError: 
        return 0, None

def guess_ctype(topic):
    try:
        return mimetypes.guess_type(topic.replace('__', '.'))[0]
    except (FileNotFoundError, TypeError): 
        return 'application/octet-stream'

def md5_digest(content):
    if content := (content.encode('utf-8') if isinstance(content, str) else content):
        return hashlib.md5(content).hexdigest()

def text_summary(content, length=54):
    if not content or not isinstance(content, str): return 'N/A'
    return re.sub(r'\s+', ' ', content)[:length] if content else 'N/A'

Article = collections.namedtuple('Article', 'topic ver ts content ctype')

# All single-topic palace operations are performed by a single function.
# This reduces the number of points of failure for the database layer.
def palace_recall(topic, /, fetch=True, store=None):
    global PALACE, TOPICS, DIR
    assert topic, 'No topic provided.'
    table, ts, sql = topic.replace('.', '__'), isotime(), None
    if isinstance(store, str): store = store.encode('utf-8')
    c = PALACE.cursor()
    try:
        if not TOPICS:
            c.execute(sql := 'SELECT name FROM sqlite_master ' 
                    'WHERE type="table" AND name not LIKE "sqlite_%"')
            for t in c.fetchall(): 
                TOPICS[t[0]] = guess_ctype(t[0])
        if topic not in TOPICS:
            c.execute(sql := f'CREATE TABLE IF NOT EXISTS {table} ('
                    f'ver INTEGER PRIMARY KEY AUTOINCREMENT, '
                    f'ts TEXT, content BLOB, md5 TEXT, mtime INTEGER)')
            mtime, seed = seed_mtime(topic)
            if seed:
                c.execute(sql := f'INSERT INTO {table} (ts, content, md5, mtime) '
                        f'VALUES (?, ?, ?, ?)', (ts, seed, md5_digest(seed), mtime))
                PALACE.commit()
            TOPICS[topic] = guess_ctype(topic)
        found = c.execute(sql := f'SELECT ver, ts, content, md5, mtime FROM {table} '
                f'ORDER BY ts DESC LIMIT 1').fetchone() if fetch else None
        if found and found[4]:
            mtime, seed = seed_mtime(topic, found[4])
            if seed and (new_seed_md5 := md5_digest(seed)) != found[3]:
                c.execute(sql := f'INSERT INTO {table} (ts, content, md5, mtime) '
                        f'VALUES (?, ?, ?, ?)', (ts, seed, new_seed_md5, mtime))
                PALACE.commit()
                found = c.execute(sql := f'SELECT ver, ts, content, md5, mtime FROM {table} '
                        f'ORDER BY ts DESC LIMIT 1').fetchone()
        store_md5 = md5_digest(store)
        if store and (not found or found[3] != store_md5):
            c.execute(sql :=f'INSERT INTO {table} (ts, content, md5, mtime) '
                    f'VALUES (?, ?, ?, ?)', (ts, store, store_md5, 0))
            emit(f'Insert commited {topic=} {len(store)=}.')
            PALACE.commit()
        if found: 
            # Never return the row directly, it's a sqlite3.Row object.
            return Article(topic, found[0], found[1], found[2], TOPICS[topic])
    except sqlite3.Error as e:
        emit(f'Palace error {e=} {sql=}'); raise
    c.close()

TopicSummary = collections.namedtuple('TopicSummary', 'topic qty ts summary')

def palace_summary():
    # TODO: Test this function (palace_summary).
    global PALACE
    c = PALACE.cursor()
    c.execute('SELECT name FROM sqlite_master WHERE type="table" '
            'AND name not LIKE "sqlite_%"')
    for t in c.fetchall():
        yield TopicSummary(t[0], *c.execute(f'SELECT COUNT(*), MAX(ts), SUBSTR(content, 0, 54) '
            f'FROM {t[0]} GROUP BY ts ORDER BY ts DESC ').fetchone())
    c.close()



# V.

import secrets
import urllib.parse
import wsgiref.simple_server 

SECRET = secrets.token_bytes()

# Functions useful for sending binary data in HTTP responses.

def hyper(content, wrap=None, iwrap=None, href=None):
    if wrap: yield f'<{wrap}>'.encode('utf-8') 
    if href: yield f'<a href="{href}">'.encode('utf-8')
    if content:
        if isinstance(content, bytes): yield content
        elif isinstance(content, str): yield content.encode('utf-8')
        elif isinstance(content, Article): yield from hyper(content.content)
        elif isinstance(content, (list, tuple, collections.abc.Generator)): 
            yield from (hyper(c, wrap=iwrap) for c in content)
        else: emit(f'Unable to encode {type(content)=} {content=}.')
    else: yield b''
    if href: yield '</a>'.encode('utf-8')
    if wrap: yield f'</{wrap}>'.encode('utf-8') 

def content_stream(env, topic):
    if not topic or env['REQUEST_METHOD'] != 'GET': return None, None
    article = palace_recall(topic)
    if article and (content := article.content):
        # Return the found article, and a generator that can be used for streaming.
        return article, (content[i:i+1024] for i in range(0, len(content), 1024))
    else: return None, None

def generate_table(headers, rows):
    yield '<table><tr>'
    for h in headers: yield f'<th>{h}</th>'
    yield '</tr>'
    for r in rows:
        yield '<tr>'
        for c in r: yield f'<td>{c}</td>'
        yield '</tr>'
    yield '</table>'

def process_forms(env, topic):
    method = env['REQUEST_METHOD']
    if method == 'POST':
        data = env['wsgi.input'].read(int(env.get('CONTENT_LENGTH', 0)))
        if topic:
            emit(f'Data received: {topic=} {len(data)=}')
            palace_recall(topic, store=data)
        return None, False
    elif method == 'GET':        
        return ('<form id="query-form" method="get">'
                '<input type="text" id="query-field" name="q" autofocus></form>'
                '<div id="query-output"></div>'), False

# Main user interface, rendered dynamically based user input.
def html_doc_stream(articles, form):
    # TODO: Why the roadmaps are not showing up?
    global SITE
    css = palace_recall('qaczar.css')
    links = []  # TODO: Add a function to generate the links.
    if not articles: articles = {palace_recall('roadmap.txt')}
    assert articles, 'No articles found.'
    yield from hyper('<!DOCTYPE html><head><meta charset="utf-8"/>')
    yield from hyper(SITE, wrap='title')  
    if css: yield from hyper(css.content, 'style')  
    yield from hyper('</head><body><nav>')   
    yield from hyper(SITE, wrap='h1', href='/')
    if links: yield from hyper(links, wrap='ul', iwrap='li')
    if form: yield from hyper(form)
    yield from hyper('</nav><main>')
    # TODO: Add a function to generate the main content.
    # TODO: The generator used depends on the number of articles combined.
    for article in articles:
        if article: yield from hyper(article, wrap='article')
        else: emit(f'Unable to render {article=}.')
    yield from hyper('</main><footer>')
    yield from hyper(f'An hypertext grimoire. Served on {isotime()}.', wrap='p')
    yield from hyper('</footer></body></html>')

# Main entrypoint for the user AND delegates. UI == API.
def facade_wsgi_responder(env, respond):
    # TODO: I think the Error 500 is because of the missing Content-Length.
    global SITE
    start = time.time()
    method, path, origin = env["REQUEST_METHOD"], env["PATH_INFO"], env["REMOTE_ADDR"]
    emit(f'--*-- Incoming {method} {path} from {origin} --*--')
    if origin != '127.0.0.1':
        emit(f'Invalid remote address {origin=}.')
        respond('403 Forbidden', [('Content-Type', 'text/plain')]); yield b''
    else:
        topics, _ = path[1:].split('?', 1) if '?' in path else (path[1:], '')
        topics, articles = topics.split('/'), set()
        for i, topic in enumerate(topics):
            topic = topic.replace('-', '_')
            article, stream = content_stream(env, topic)
            articles.add(article)
            if i == 0:
                if article and len(topics) == 1 and '.' in topic:
                    ctype = article.ctype or 'application/octet-stream'
                    respond('200 OK', [('Content-Type', ctype),
                            ('Content-Length', str(len(article.content)))])
                    yield from stream; break
                else:
                    form, redirect = process_forms(env, topic)
                    if redirect:
                        emit(f'Redirecting to {redirect=}.')
                        respond('303 See Other', [('Location', redirect)])
                        yield b''; break
                    else:
                        respond('200 OK', [('Content-Type', 'text/html; charset=utf-8')])
        else:
            # I am so happy I found a use case for the else clause of a for loop.
            emit(f'Generating HTML document {len(articles)=}.')
            yield from html_doc_stream(articles, form)
    emit(f"Request completed at {round(time.time() - start, 2)} % capacity.")

class Unhandler(wsgiref.simple_server.WSGIRequestHandler):
    def log_request(self, *args, **kwargs): pass

if __name__ == "__main__" and RUNLEVEL == 2:
    PALACE =  sqlite3.connect('p.sqlite', isolation_level='IMMEDIATE')
    atexit.register(PALACE.close)
    HOST, PORT = sys.argv[1].split(':')
    PORT = int(PORT)
    palace_recall('qaczar.py', store=SOURCE)
    with wsgiref.simple_server.make_server(
            HOST, PORT, facade_wsgi_responder, handler_class=Unhandler) as s:
        emit(f'Facade ready. Serving on http://{HOST}:{PORT}/')
        create_fork(sys.argv[1], 'certify_build')
        s.serve_forever(poll_interval=1)


# H.

import urllib.request

def request_facade(*args, upload=None):
    assert all(urllib.parse.quote(arg) == arg for arg in args), f"Invalid request {args=}"
    url = f'http://{HOST}:{PORT}/{"/".join(args)}'
    try:
        upload = upload.encode('utf-8') if upload else None
        with urllib.request.urlopen(url, data=upload, timeout=6) as r:
            return r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        emit(f'HTTPError: {e.code}'); raise e

def chain_run(*cmds, s=None):
    for cmd in cmds:
        try:
            if s is not None and s.returncode != 0: return s.returncode
            s = subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except (subprocess.CalledProcessError, RuntimeError) as e:
            emit(f'Command error: {e=}')
            return s.returncode if s else -1
    return s.returncode

# TODO: Create a new kind of scheduler (cron) delegate.
    
def certify_build():
    global BRANCH
    roadmap = []
    for ln, line in enumerate(SOURCE.splitlines()):
        if line.strip().startswith('# TODO:'):
            roadmap.append(f'@{ln+1:04d} {line.strip()[7:]}')
    roadmap = '\n'.join(roadmap)
    request_facade('roadmap.txt', upload=roadmap)
    found = palace_recall('roadmap.txt')
    if not found or found.content.decode('utf-8') != roadmap:
        emit(f'Roadmap updated: {len(roadmap)=} {len(found[3])=}')
        emit('Roadmap not updated properly.'); sys.exit(1)
    return chain_run(
            ['git', 'add', '.'],
            ['git', 'commit', '-m', 'Automatic commit by certify_build.'],
            ['git', 'push', 'origin', BRANCH])

if __name__ == "__main__" and RUNLEVEL == 3:
    GOAL = sys.argv[2]
    emit(f'Delegate of <{HOST}:{PORT}> preparing to <{GOAL}>.')
    assert PALACE is None, 'Palace already connected. Not good.'
    PALACE =  sqlite3.connect('file:p.sqlite?mode=ro', uri=True)
    for task in GOAL.split(':'):
        try: 
            task = globals()[GOAL]
        except KeyError as e:
            emit(f'No such task <{GOAL=}>.'); sys.exit(1)
        try:
            if last_return := task():
                emit(f'Task <{GOAL}> completed: {last_return=}')
                continue
            emit(f'Task <{GOAL}> executed with no result.'); sys.exit(1)
        except Exception as e:
            emit(f'Task error: {e=}'); sys.exit(1)

# TODO: Think about how to deploy to AWS after SSL is working.            
# TODO: Think of new functions to add to qaczar.
