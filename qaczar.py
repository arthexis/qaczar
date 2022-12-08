#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script designed to experiment with rapid application development.
# H. V. D. C. by Rafa Guillén (arthexis@gmail.com) 2022-2023

# - Keep the line width to less than 100 characters.
# - Use functions, not classes, for modularity, composability and encapsulation.
# - Functions should not reference functions or globals from later in the script.
# - Prioritize stability and clarity over features.

import os
import sys
import time
import atexit
import typing as t
import subprocess as sp
import xml.dom.minidom as dom


RUNLEVEL = 0
HOME = '/qaczar.html'


def now() -> str:  # Time in UTC ISO format.
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str) -> None: 
    f = sys._getframe(1)  # Caller's frame.
    print(f'[{RUNLEVEL}:{f.f_lineno}] [{now()}] {f.f_code.co_name}: {msg}')

def halt(msg: str, code: int=1) -> t.NoReturn:
    emit(msg + " Halting."); sys.exit(code)

def read(fname: str, encoding=None) -> bytes:
    with open(fname, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def write(fname: str, data: bytes | str, encoding=None) -> None:
    with open(fname, 'wb' if not encoding else 'w', encoding=encoding) as f: f.write(data)

def mtime(fname: str) -> float:
    return os.path.getmtime(fname)

def run(*args: list[str]) -> sp.Popen:
    s = sp.Popen([sys.executable, *[str(a) for a in args]])
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"{s.args=} {s.pid=}.")
    return s

def restart(s: sp.Popen = None) -> sp.Popen:
    s.terminate(); s.wait()
    atexit.unregister(s.terminate)
    args = s.args + (os.getpid(),) if s.args[0] == __file__ else args
    return run(*args)

# Watch over s to ensure it never dies. If it does, create a new one.
def watch_over(s: sp.Popen, fname: str) -> t.NoReturn:  
    source, old_mtime, stable = read(fname), mtime(fname), True
    while True:
        time.sleep(2.6)
        if (new_mtime := mtime(fname)) != old_mtime:
            mutation, old_mtime = read(fname), new_mtime
            if mutation != source:
                emit(f"Mutation detected. Restart {fname=}.")
                s, stable = restart(s), False
            continue
        if s.poll() is not None:
            if s.returncode == 0:
                halt(f"Process {s.pid} exited normally.")
            if stable:
                emit(f"Script died {s.args=} {s.pid=}. Restarting.")
                s, stable = restart(s), False
                continue
            if (mutation := read(fname)) != source:
                emit(f"Rolling back {fname=}.")
                write(fname, source)
                s = restart(s)
                continue
            halt(f"Unstable {fname=}. Check source.")
        if not stable:
            emit(f"Stabilizing {s.pid=}.")
            source, stable = read(fname), True
            
def watch_self(watcher=None):
    if watcher: os.kill(int(watcher), 9)
    watch_over(run(__file__, __file__), __file__)

def dedent(code: str) -> str:
    indent = len(code) - len(code.lstrip()) - 1
    return '\n'.join(line[indent:] for line in code.splitlines())

def timed(f):
    def timed(*args, **kwargs):
        start = time.time()
        result = f(*args, **kwargs)
        emit(f"{f.__name__} took {time.time() - start:.2f} seconds.")
        return result
    return timed

@timed
def process_html(fname: str, context: dict) -> None:
    # TODO: Handle form submissions.
    document = dom.parseString(read(fname, encoding='utf-8'))
    context['document'] = document
    for node in document.getElementsByTagName('script'):
        if node.getAttribute('type') == 'text/python':
            code = dedent(node.firstChild.data)
            exec(code, None, context)
            node.parentNode.removeChild(node)
    write(os.path.join('.work', fname), document.toxml(), encoding='utf-8')

# Start a wsgi server that serves the current directory.
def serve_forever(host, port) -> t.NoReturn:
    global HOME
    import http.server as hs
    import socketserver as ss
    from urllib.parse import parse_qs
    if not os.path.exists('.work'): os.mkdir('.work')

    class Handler(hs.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            emit(f"{self.address_string()} {format % args}")

        def specialize(self, method: str = None):
            path = HOME if self.path == '/' else self.path
            if '?' in path: path, qs = path.split('?', 1)
            else: qs = ''
            if path.endswith('.html'):
                context = {'get': parse_qs(qs)}
                if method == 'POST':
                    length = int(self.headers.get('content-length', 0))
                    context['post'] = parse_qs(self.rfile.read(length).decode('utf-8'))
                else: context['post'] = {}
                process_html(path[1:], context)
                self.path = f'/.work{path}'
            elif path.endswith('.py'):
                # TODO: Ponder what to do with requested py files.
                # Maybe run a checksum to make sure they are legit?
                # Should we somehow import them?
                pass

        def do_HEAD(self) -> None:
            self.specialize('HEAD'); return super().do_HEAD()
            
        def do_GET(self) -> None:
            self.specialize('GET'); return super().do_GET()
        
        def do_POST(self) -> None:
            self.specialize('POST'); return super().do_GET()
        
    with ss.TCPServer((host, int(port)), Handler) as httpd:
        emit(f"Serving at http://{host}:{port}")
        httpd.serve_forever()

def main_loop(pid:str=None, server:str=None, *args: list[str]) -> t.NoReturn:
    emit(f"Starting {pid=} {args=}.")
    if pid is not None:
        emit(f"Kill watcher {pid=}. Become our own watcher.")
        watch_self(watcher=pid)
    serve_forever('localhost', 8080)

# Begin script execution in watch mode.
if __name__ == "__main__":
    RUNLEVEL = 1
    if len(sys.argv) == 1:
        watch_self()
    elif sys.argv[1] == __file__:
        RUNLEVEL = 2
        main_loop(*sys.argv[2:])
    watch_over(run(*sys.argv[1:]), sys.argv[1])
