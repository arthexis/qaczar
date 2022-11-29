#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script that does everything by itself.
# (aka. one night a mysterious cosmic voice told me to create an ark and here it is)
# H. V. D. C. by Rafa Guillén (arthexis@gmail.com) 2022-2023

# 1. Keep the line width to less than 100 characters.
# 2. Use functions, not classes, for modularity, composability and encapsulation.
# 3. Functions should not reference functions or globals from later in the script.
# 4. The system must respond to all requests in 1 second or less.
# 5. Don't overdesign, wait until the opportunity for reuse arises and take it.


import os
import sys
import time
import atexit
import subprocess

# We don't import everything at the start to keep the runtime of 
# the crown (watcher) as simple as possible. Later we can import more modules.

# This is the name that will appear on the title of the website.
SITE = 'QACZAR.COM'
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

HOST = os.environ.get('QACZAR_HOSTNAME', 'localhost')
PORT = int(os.environ.get('QACZAR_PORT', 8080)) 

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
                emit(f"Unstable crown, aborting. Check {__file__} for errors.")
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
        return (mimetypes.guess_type(topic.replace('__', '.'))[0]
            or 'application/octet-stream')
    except (FileNotFoundError, TypeError): 
        return 'application/octet-stream'

def md5_digest(content):
    if content := (content.encode('utf-8') if isinstance(content, str) else content):
        return hashlib.md5(content).hexdigest()

def text_summary(content, length=54):
    if not content or not isinstance(content, str): return 'N/A'
    return re.sub(r'\s+', ' ', content)[:length] if content else 'N/A'

def sqlite_tableset(prefix=None):
    global PALACE
    c = PALACE.cursor()
    if prefix:
        c.execute(f'SELECT name FROM sqlite_master WHERE type="table" '
                f'AND name LIKE "{prefix}_%" and name NOT LIKE "sqlite_%";')
    else:
        c.execute('SELECT name FROM sqlite_master '
            'WHERE type="table" and name NOT LIKE "sqlite_%";')
    offset = len(prefix) + 1 if prefix else 0
    for t in c.fetchall():
        yield t[0][offset:]
    c.close()

Article = collections.namedtuple('Article', 'topic ver ts content ctype')

# All single-topic palace operations are performed by a single function.
# This reduces the number of points of failure for the database layer.
def palace_recall(topic, /, fetch=True, store=None, append=False):
    global PALACE, TOPICS, DIR
    # TODO: Add a TTL column to the topic tables, and use it to prune old data.
    ts, sql = isotime(), None
    c = PALACE.cursor()
    try:
        table = 'top_' + topic.replace('.', '__')
        assert topic and isinstance(topic, str), f'Invalid topic {topic=}.'
        if isinstance(store, (tuple, list)): store = '\n'.join(store)
        if isinstance(store, str): store = store.encode('utf-8')
        if not TOPICS: TOPICS = {t: guess_ctype(t) for t in sqlite_tableset('top')}
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
                f'ORDER BY ts DESC LIMIT 1').fetchone() if fetch or append else None
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
            if not append or not found:
                c.execute(sql :=f'INSERT INTO {table} (ts, content, md5, mtime) '
                        f'VALUES (?, ?, ?, ?)', (ts, store, store_md5, 0))
                emit(f'Insert commited {topic=} {len(store)=}.')
                PALACE.commit()
        if found: 
            ctype = TOPICS.get(topic, 'application/octet-stream')
            if append and store:
                c.execute(sql := f'UPDATE {table} SET content = ?, ts = ?, md5 = ? '
                        f'WHERE ver = ?', (found[2] + store, ts, store_md5, found[0]))
                PALACE.commit()
            return Article(topic, found[0], found[1], found[2], ctype)
    except Exception as e:
        lineno = sys._getframe(1).f_lineno
        caller = sys._getframe(1).f_code.co_name
        emit(f'Palace error {e=} {caller=} {lineno=} {sql=}'); raise
    c.close()

TopicSummary = collections.namedtuple('TopicSummary', 'topic ver ts length ctype')

def palace_summary(prefix=None):
    global PALACE
    c = PALACE.cursor()
    for topic in sqlite_tableset('top'):
        if prefix and not topic.startswith(prefix): continue
        found = c.execute(f"SELECT MAX(ver), MAX(ts), length(content) "
            f'FROM top_{topic} GROUP BY ts ORDER BY ts DESC ').fetchone()
        if found: 
            ctype = TOPICS.get(topic, "application/octet-stream")
            yield TopicSummary(topic, found[0], found[1], int(found[2]), ctype)
    c.close()


# V.

import html
import urllib.parse
import wsgiref.simple_server 

# Functions useful for sending binary data in HTTP responses.

def format_table(headers, rows, title=None):
    assert isinstance(headers, dict) 
    # The output should already be binary encoded for performance.
    if title: yield f'<h2>{title}</h2>'.encode('utf-8')
    if not rows: 
        yield '<p><strong>No data found.</strong></p>'.encode('utf-8')
    else:
        yield b'<table><tr>'
        for h in headers.keys(): yield f'<th>{h}</th>'.encode('utf-8')
        yield b'</tr>'
        for r in rows:
            yield b'<tr>'
            for c, t in zip(r, headers.values()):
                if t is None: yield f'<td>{c}</td>'.encode('utf-8')
                elif t == 'a': 
                    yield f'<td><a href="{c}">{c}</a></td>'.encode('utf-8')
                else: yield f'<td><{t}>{c}</{t}></td>'.encode('utf-8')
            yield b'</tr>'
        yield b'</table>'

def format_python_line(line):
    line = html.escape(line)
    line = line.replace('  ', '&nbsp;').replace('\t', '&nbsp;&nbsp;')
    yield b'<code>'
    if line.strip().startswith('#'): yield f'<q>{line}</q>'.encode('utf-8')
    elif line.startswith('def') or line.startswith('import'):
        yield f'<strong>{line}</strong>'.encode('utf-8')
    elif 'except' in line or 'return' in line or 'yield' in line: 
        yield f'<mark>{line}</mark>'.encode('utf-8')
    else: yield line.encode('utf-8')
    yield b'</code>'

def format_css_line(line):
    line = line.replace('  ', '&nbsp;').replace('\t', '&nbsp;&nbsp;')
    yield b'<code>'
    if line.strip().startswith('/*'): yield f'<q>{line}</q>'.encode('utf-8')
    elif line.strip().endswith('{'): yield f'<mark>{line}</mark>'.encode('utf-8')
    else: yield line.encode('utf-8')
    yield b'</code>'
    
def format_codelines(lines, formater=None):
    yield b'<ol>'
    for i, line in enumerate(lines):
        yield b'<li>'
        if formater: yield from formater(line)
        else: yield line.encode('utf-8')
        yield b'</li>'
    yield b'</ol>'

def format_article(article, aside=None):
    yield f'<article><h2>{article.topic}</h2><ol>'.encode('utf-8')
    ctype, formatter = article.ctype, None
    if ctype.startswith('text/'):
        if ctype == 'text/html': yield article.content
        else:
            content = article.content.decode('utf-8').splitlines()
            if ctype == 'text/x-python': formatter = format_python_line
            if ctype == 'text/css': formatter = format_css_line
            yield from format_codelines(content, formater=formatter)
    elif article.ctype == 'application/octet-stream':
        fname = article.topic.replace('__', '.')
        yield (f'<p><strong>Unable to visualize content of type {article.ctype}</strong>.</p>'
            f'<p><a href="{fname}">Click here to download {fname}</a></p>').encode('utf-8')
    if aside: yield f'<aside>{aside}</aside>'.encode('utf-8')
    yield b'</article>'

def format_stream(env, topic):
    # This is necesary to avoid the browser from buffering the entire response.
    if not topic or env['REQUEST_METHOD'] != 'GET': return None, None
    article = palace_recall(topic)
    if article and (content := article.content):
        # Return the found article and a generator that can be used for streaming.
        return article, (content[i:i+1024] for i in range(0, len(content), 1024))
    else: return None, None

def process_query(query, topic=None):
    form, redirect = None, None
    content = b'<h2>Inline query</h2>' + b'<p><strong>Not implemented yet.</strong></p>'
    return content, form, redirect

def process_forms(env, topic):
    # Returns the query form html, and redirect url if needed.
    method, msg, form = env['REQUEST_METHOD'], '', None
    if method == 'POST':
        data = env['wsgi.input'].read(int(env.get('CONTENT_LENGTH', 0)))
        if topic:
            emit(f'Data received: {topic=} {len(data)=}')
            palace_recall(topic, store=data)
        return None, False
    elif method == 'GET': 
        if query := urllib.parse.unquote(env.get('QUERY_STRING', '')):
            vars = urllib.parse.parse_qs(query); q = vars["q"][0]
            # TODO: Remove ! from the report name.
            if q.startswith('!'):
                report = q[1:].replace(' ', '_') + '__html'
                content, form, redirect = process_query(q[1:], topic)
                if report and content: palace_recall(report, store=content, append=True)
                if redirect: return None, redirect
                msg = (f"Completed query='{q}' on {topic=}. "
                    f"Report: <a href='{report}'>{report}</a>.")
            else:
                report = q.replace(' ', '_') + '__html'
                msg = (f"Delegated query='{q}' on {topic=}. "
                    f"Report: <a href='{report}'>{report}</a>.")
                delegation = query.replace('+', '_')
                palace_recall(report, store='<strong>Delegate in progress...</strong>')
                create_fork(f'{HOST}:{PORT}', delegation)
            return None, report
        return form or (f'<form id="query-form" method="get">'
                f'<input type="text" id="query-field" name="q" accesskey="q">'
                f'</form><span id="query-output">{msg}</span>'), False

def hyper(content, wrap=None, iwrap=None, href=None):
    if wrap: yield f'<{wrap}>'.encode('utf-8') 
    if href: yield f'<a href="{href}">'.encode('utf-8')
    if content:
        if isinstance(content, bytes): yield content
        elif isinstance(content, str): yield content.encode('utf-8')
        elif isinstance(content, Article): yield from hyper(content.content)
        elif isinstance(content, (list, tuple, collections.abc.Generator)): 
            for c in content: yield from hyper(c, wrap=iwrap)
        else: emit(f'Unable to encode {type(content)=} {content=}.')
    else: yield b''
    if href: yield b'</a>'
    if wrap: yield f'</{wrap}>'.encode('utf-8') 
      
def article_combinator(articles):
    if not articles:
        # This is the overview page, when no topic is specified.
        th = {'Topic': 'a', 'Ver': None, 'Timestamp': 'time', 'Size': None, 'Type': 'q'}
        g = (x for x in format_table(th, palace_summary(), 'Palace Summary'))
        yield from hyper(g, wrap='article')
        articles = {palace_recall('roadmap.txt')}
    for article in articles:
        # TODO: Find something more interesting for the combinator.
        if not article: continue
        if not article.content: 
            yield from hyper(f'No content found for {article.topic}.', wrap='p')
        else: yield from format_article(article)

# Main user interface, rendered dynamically based user input.
def html_doc_stream(articles, form):
    global SITE
    css = palace_recall('qaczar.css')
    # TODO: Links should be generated for alternate views (e.g. txt, json, etc.)
    # TODO: Use accesskey="#" and number the links.
    links = []  
    yield from hyper('<!DOCTYPE html><head><meta charset="utf-8"/>')
    if not form: yield from hyper(f'<meta http-equiv="refresh" content="6"/>')
    yield from hyper(SITE, wrap='title')  
    if css: yield from hyper(css.content, 'style')  
    yield from hyper('</head><body><nav>')   
    yield from hyper(SITE, wrap='h1', href='/')
    if links: yield from hyper(links, wrap='ul', iwrap='li')
    if form: yield from hyper(form)
    yield from hyper('</nav><main>')
    yield from article_combinator(articles)
    yield from hyper('</main><footer>')
    yield from hyper(f'An hypertext grimoire. Served on {isotime()}.', wrap='p')
    # TODO: Add suggested navigation links (maybe to other sites).
    yield from hyper('</footer></body></html>')

def http_headers(ctype='text/html; charset=utf-8', redirect=None, size=None):
    if redirect: return [('Location', redirect)]
    headers = [('Content-Type', ctype or 'application/octet-stream')] 
    if size: headers.append(('Content-Length', str(size)))
    return headers

FIRST_VISIT = True
ALLOWLIST = os.environ.get('ALLOWLIST', '').split()

# Main entrypoint for the user AND delegates. UI == API.
def facade_wsgi_responder(env, start_response):
    global ALLOWLIST, FIRST_VISIT
    write, start = None, time.time()
    method, path, origin = env["REQUEST_METHOD"], env["PATH_INFO"], env["REMOTE_ADDR"]
    emit(f'--*-- Incoming {method} {path} from {origin} --*--')
    if origin != '127.0.0.1' and origin not in ALLOWLIST:
        write = start_response('403 Forbidden', http_headers())
    else:
        topics, _ = path[1:].split('?', 1) if '?' in path else (path[1:], '')
        topics, articles, form = topics.split('/'), set(), None
        for i, topic in enumerate(topics):
            topic = topic.replace('-', '_')
            article, stream = format_stream(env, topic)
            if i == 0:
                if article and len(topics) == 1 and '.' in topic:
                    size = len(article.content)
                    write = start_response('200 OK', http_headers(article.ctype, size=size))
                    yield from stream
                else:
                    form, redirect = process_forms(env, topic)
                    if redirect:
                        write = start_response('303 See Other', http_headers(redirect=redirect))
            if article: articles.add(article)
        else:  # Actual use case for the else clause of a for loop.
            if not write: 
                write = start_response('200 OK', [('Content-Type', 'text/html; charset=utf-8')])
            yield from  html_doc_stream(articles, form)
    capacity = round(time.time() - start, 2)
    emit(f"Request completed at {capacity} % capacity.")
    # TODO: Add performance information to the visit log.
    palace_recall('visitors__txt', fetch=False, 
        store=f'<time>{isotime()}</time> {origin} {method} {path} {capacity}\n', append=not FIRST_VISIT)
    FIRST_VISIT = False

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
        create_fork(sys.argv[1], 'self_check')
        s.serve_forever(poll_interval=6)


# H.

import urllib.request

DELEGATE = None
REPORT = []

def emit(verse, safe=False):
    global DELEGATE, REPORT
    ts = isotime()
    print(f'[{RUNLEVEL}:{sys._getframe(1).f_lineno}] [{ts}] {DELEGATE}: {verse}')
    if not safe:
        verse = '<code>' + html.escape(verse) + '</code>'
    REPORT.append(f'<li><time>{ts}</time> {verse}</li>')

def facade_request(*args, upload=None):
    assert all(urllib.parse.quote(arg) == arg for arg in args), f"Invalid request {args=}"
    url = f'http://{HOST}:{PORT}/{"/".join(args)}'
    try:
        if isinstance(upload, (list, tuple)): upload = '\n'.join(upload).encode('utf-8')	
        if isinstance(upload, str): upload = upload.encode('utf-8')
        with urllib.request.urlopen(url, data=upload, timeout=6) as r:
            return r.status, r.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        emit(f'HTTPError: {e.code}'); raise e
    
# TODO: New function to download data from an external source.

def chain_run(*cmds, s=None):
    for cmd in cmds:
        try:
            if s is not None and s.returncode != 0: return s.returncode
            s = subprocess.run(cmd, shell=True, check=True, capture_output=True)
        except (subprocess.CalledProcessError, RuntimeError) as e:
            emit(f'Command failed with error: {e=}.')
            return s.returncode if s else -1
    return s.returncode

CORE_FUNCTIONS = {}

def delegate_task():
    global HOST, PORT, DELEGATE, CONTEXT, REPORT, CORE_FUNCTIONS
    emit(f'Delegate "{DELEGATE}" of "{HOST}:{PORT}" starting.')
    # Import qaczar itself to access functions from the future.
    import qaczar
    qaczar.emit = emit  
    delegate = getattr(qaczar, DELEGATE, None)
    assert callable(delegate), f'Invalid delegate {delegate=}.'
    assert delegate not in CORE_FUNCTIONS, f"Core function {delegate=} not allowed."
    if delegate.__code__.co_argcount: 
        context = facade_request(CONTEXT) if context else None
        emit(f'Received {len(context) + " bytes of" if context else "no"} context.')
        delegate(context)  
    else: 
        if CONTEXT: emit(f'Context <{CONTEXT}> ignored for delegate <{DELEGATE}>.')
        delegate()
    if REPORT:
        status, _ = facade_request(f'{DELEGATE}__html', upload=REPORT)
        emit(f'Delegate "{DELEGATE}" completed and reported with {status=}.')
    else: emit(f'Delegate "{DELEGATE}" completed without reporting.')

CORE_FUNCTIONS = {f for f in globals().values() if callable(f)}

if __name__ == "__main__" and RUNLEVEL in (3, 4):
    BASE_HOST, BASE_PORT = sys.argv[1].split(':')
    BASE_PORT = int(BASE_PORT)
    DELEGATE = sys.argv[2].lower()
    CONTEXT = sys.argv[3] if len(sys.argv) > 3 else None
    assert PALACE is None, 'Palace connected. Not good.'
    if HOST != BASE_HOST:
        PALACE =  sqlite3.connect('p.sqlite', isolation_level='IMMEDIATE')
    delegate_task()


# --- Delegate-only functions go below this line. ---
# Delegates can access core functions, but not other delegates.
    
def self_check():
    global BRANCH, SOURCE
    import platform
    emit(f'Validating build of {BRANCH=}.')
    facade_request('platform.txt', upload=(
        f'{platform.node()=}\n'
        f'{platform.machine()=}\n'
        f'{platform.platform()=}\n'
        f'{platform.python_version()=}\n'
        f'{sys.executable=}\n'
        f'{DIR=}\n'
        f'{BRANCH=}\n'
    ))
    roadmap = []
    for ln, line in enumerate(SOURCE.splitlines()):
        if line.strip().startswith('# TODO:'):
            roadmap.append(f'@{ln+1:04d} {line.strip()[7:]}')
    roadmap = '\n'.join(roadmap)
    status, _ = facade_request('roadmap.txt', upload=roadmap)
    emit(f'Roadmap uploaded {status=}.')
    if status != 200: return status
    returncode = chain_run(
            ['git', 'add', '.'],
            ['git', 'commit', '-m', 'Commit by self_check.'],
            ['git', 'push', 'origin', BRANCH])
    emit(f'Pushed to {BRANCH=} {returncode=}.')
    emit(f'Validation and push completed.')

# TODO: Create a delegate that replays requests from a visitor log.
# TODO: New delegate to run a script in a virtual environment.
# TODO: Prune unnecessary functions from delagates before running them.
# TODO: Think about new ways to visualize the code.
# TODO: Think about how to deploy to AWS after SSL is working.     
# TODO: Consider using black to reduce the number of cache updates.       
# TODO: Think of ART or GAME FUNCTIONS to add to qaczar.

