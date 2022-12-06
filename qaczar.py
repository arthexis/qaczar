#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A Python script designed to experiment with rapid application development.
# H. V. D. C. by Rafa Guillén (arthexis@gmail.com) 2022-2023

# 1. Keep the line width to less than 100 characters.
# 2. Use functions, not classes, for modularity, composability and encapsulation.
# 3. Functions should not reference functions or globals from later in the script.
# 4. The system must respond to all requests in 1 second or less.
# 5. Don't overdesign, wait until the opportunity for reuse arises and take it.
# 6. Accomplish everything in under 4000 lines of code.
# 7. Prioritize stability over features.

import os
import sys
import time
import socket
import atexit
import typing as t
import subprocess as sp


RUNLEVEL = 0


# General purpose functions.

def isotime() -> str: 
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str) -> None: 
    f = sys._getframe(1)
    print(f'[{RUNLEVEL}:{f.f_lineno}] [{isotime()}] {f.f_code.co_name}: {msg}')

def terminate(msg: str, code: int=1) -> t.NoReturn:
    emit(msg + " Terminating."); sys.exit(code)

def read_bytes(fname: str) -> bytes:
    with open(fname, 'rb') as f: return f.read()
    
def write_bytes(fname: str, data: bytes) -> None:
    with open(fname, 'wb') as f: f.write(data)

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
    source, mtime, stable = read_bytes(fname), os.path.getmtime(fname), True
    while True:
        time.sleep(2.6)
        if os.path.getmtime(fname) != mtime:
            mutation, mtime = read_bytes(fname), os.path.getmtime(fname)
            if mutation != source:
                emit(f"Mutation detected. Restart {fname=}.")
                # Make the new mutation start with a new main.
                s, stable = restart_script(s), False
            continue
        if s.poll() is not None:
            if s.returncode == 0:
                terminate(f"Process {s.pid} exited normally.")
            if stable:
                emit(f"Fork died {s.args=} {s.pid=}. Restarting.")
                s, stable = restart_script(s), False
                continue
            if (mutation := read_bytes(fname)) != source:
                emit(f"Rolling back {fname=}.")
                write_bytes(fname, source)
                s, stable = restart_script(s), False
                continue
            else:
                if mutation != source: write_bytes(fname, mutation)
                terminate(f"Unstable {fname=}. Check source for errors.")
        if not stable:
            emit(f"Stabilizing {s.pid=}.")
            source, stable = read_bytes(fname), True

def watch_self(watcher=None):
    if watcher: os.kill(int(watcher), 9)
    watch_over(start_script(__file__, __file__), __file__)

def list_files():
    return [f for f in os.listdir() if not f.startswith(('__', '.'))]

def main_loop(pid=None, *args: list[str]) -> t.NoReturn:
    emit(f"Starting {pid=} {args=}.")
    if pid is not None: 
        emit(f"Kill watcher {pid=}. Activate self watch.")
        watch_self(watcher=pid)
    while True:
        # TODO: Decide what to do here.
        emit(f"Looping {pid=} {args=}.")
        # Get a list of all the files in the current directory.
        # Exclude files that start with __ or .
        files = [f for f in os.listdir() if not f.startswith(('__', '.'))]
        emit(f"Files: {files}")
        time.sleep(6.0)

# Start a wsgi server that serves the current directory.
def start_server():
    pass

# Begin script execution in watch mode.
if __name__ == "__main__":
    RUNLEVEL = 1
    if len(sys.argv) == 1:
        watch_self()
    elif sys.argv[1] == __file__:
        RUNLEVEL = 2
        main_loop(*sys.argv[2:])
    watch_over(start_script(*sys.argv[1:]), sys.argv[1])

        