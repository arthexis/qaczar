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


def isotime() -> str:  # Time in UTC ISO format.
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str) -> None: 
    f = sys._getframe(1)  # Caller's frame.
    print(f'[{RUNLEVEL}:{f.f_lineno}] [{isotime()}] {f.f_code.co_name}: {msg}')

def halt(msg: str, code: int=1) -> t.NoReturn:
    emit(msg + " Halting."); sys.exit(code)

def read_bytes(fname: str, encoding=None) -> bytes:
    with open(fname, 'rb' if not encoding else 'r', encoding=encoding) as f: return f.read()
    
def write_bytes(fname: str, data: bytes | str, encoding=None) -> None:
    with open(fname, 'wb' if not encoding else 'w', encoding=encoding) as f: 
        f.write(data)
        f.flush()

def get_mtime(fname: str) -> float:
    return os.path.getmtime(fname)


def start_script(*args: list[str]) -> sp.Popen:
    s = sp.Popen([sys.executable, *[str(a) for a in args]])
    s.stdout, s.stderr, s.args = sys.stdout, sys.stderr, args
    atexit.register(s.terminate)
    emit(f"{s.args=} {s.pid=}.")
    return s

def restart_script(s: sp.Popen = None) -> sp.Popen:
    s.terminate(); s.wait()
    atexit.unregister(s.terminate)
    args = s.args + (os.getpid(),) if s.args[0] == __file__ else args
    return start_script(*args)


# Watch over s to ensure it never dies. If it does, create a new one.
def watch_over(s: sp.Popen, fname: str) -> t.NoReturn:  
    source, mtime, stable = read_bytes(fname), get_mtime(fname), True
    while True:
        time.sleep(2.6)
        if (_mtime := get_mtime(fname)) != mtime:
            mutation, mtime = read_bytes(fname), _mtime
            if mutation != source:
                emit(f"Mutation detected. Restart {fname=}.")
                s, stable = restart_script(s), False
            continue
        if s.poll() is not None:
            if s.returncode == 0:
                halt(f"Process {s.pid} exited normally.")
            if stable:
                emit(f"Script died {s.args=} {s.pid=}. Restarting.")
                s, stable = restart_script(s), False
                continue
            if (mutation := read_bytes(fname)) != source:
                emit(f"Rolling back {fname=}.")
                write_bytes(fname, source)
                s = restart_script(s)
                continue
            halt(f"Unstable {fname=}. Check source.")
        if not stable:
            emit(f"Stabilizing {s.pid=}.")
            source, stable = read_bytes(fname), True

            
def watch_self(watcher=None):
    if watcher: os.kill(int(watcher), 9)
    watch_over(start_script(__file__, __file__), __file__)


def process_html(fname: str) -> None:
    start = time.time()
    document = dom.parseString(read_bytes(fname, encoding='utf-8'))
    for node in document.getElementsByTagName('script'):
        if node.getAttribute('type') == 'text/python':
            emit(f"Executing {fname=} {node.nodeName=} {node.getAttribute('type')=}.")
            code = node.firstChild.data
            indent = len(code) - len(code.lstrip()) - 1
            code = '\n'.join(line[indent:] for line in code.splitlines())
            exec(code, globals(), locals())
            node.parentNode.removeChild(node)   
    write_bytes(os.path.join('.work', fname), document.toxml(), encoding='utf-8')
    emit(f"Processed {fname=} in {time.time() - start:.2f} seconds.")

# Start a wsgi server that serves the current directory.
def serve_forever(host, port) -> t.NoReturn:
    import http.server as hs
    import socketserver as ss
    # Create a work directory for preprocessed files.
    
    if not os.path.exists('.work'): os.mkdir('.work')
    cache = {}  # Type: dict[str, (bytes, float)]
    class Handler(hs.SimpleHTTPRequestHandler):
        def log_message(self, format, *args):
            emit(f"{self.address_string()} {format % args}")
        def do_GET(self) -> None:
            if self.path[1] in '._': return self.send_error(404)
            ext = self.path[1:].split('.')[-1] if '.' in self.path else None
            if ext == 'html':
                process_html(self.path[1:])
                self.path = '/.work' + self.path
                emit(f"Preprocessed {self.path=}.")
            return super().do_GET()
    with ss.TCPServer((host, int(port)), Handler) as httpd:
        source = read_bytes(__file__, encoding='utf-8')
        emit(f"Serving at http://{host}:{port}")
        httpd.serve_forever()

# Main loop that starts at the very end of the script.
def main_loop(pid:str=None, server:str=None, *args: list[str]) -> t.NoReturn:
    emit(f"Starting {pid=} {args=}.")
    if pid is not None:
        emit(f"Kill watcher {pid=}. Become self-watcher.")
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
    watch_over(start_script(*sys.argv[1:]), sys.argv[1])
