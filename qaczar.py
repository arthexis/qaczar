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
import atexit
import subprocess
import typing as t


MAIN = 'smoke_test'
RUNLEVEL = len(sys.argv)

def isotime() -> str: 
    return time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime())

def emit(msg: str) -> None: 
    f = sys._getframe(1)
    print(f'[{RUNLEVEL}:{f.f_lineno}] [{isotime()}] {f.f_code.co_name}: {msg}')

def fread(fn: str, decode: str = None) -> bytes:
    try: 
        with open(fn, 'r' if decode else 'rb', encoding=decode) as f:  
            return f.read()
    except FileNotFoundError: 
        return None 

SOURCE = fread(__file__, decode='utf-8')

# Create a running copy of ourselves with extra arguments.
def create_fork(*args: list[str], old: subprocess.Popen = None) -> subprocess.Popen:
    assert len(args) > 0, 'No args provided to create_fork.'
    if old is not None:
        old.terminate()
        old.wait()
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
def watch_over(s: subprocess.Popen) -> t.NoReturn:  
    global SOURCE
    while True:
        stable, mtime = True, os.path.getmtime(__file__)
        while True:
            time.sleep(1)
            if os.path.getmtime(__file__) != mtime:
                mutation, mtime = fread(__file__), os.path.getmtime(__file__)
                if mutation != SOURCE:
                    emit(f"Mutation detected {len(mutation)=} {len(SOURCE)=}. Restarting.")
                    # Make the new mutation start with a new main.
                    s, stable = create_fork(*s.args, old=s), False
                continue
            if s.poll() is not None:
                if s.returncode == 0:
                    emit(f"Process {s.pid} exited normally. Terminating.")
                    sys.exit(0)
                if stable:
                    emit(f"Fork died {s.args=} {s.pid=}. Restarting.")
                    s, stable = create_fork(*s.args, old=s), False
                    continue
                mutation = fread(__file__, decode='utf-8')
                if mutation != SOURCE:
                    emit(f"Rolling back mutation {len(mutation)=} {len(SOURCE)=}.")
                    # Overwrite the mutation with the original source.
                    with open(__file__, 'w', encoding='utf-8') as f:
                        f.write(SOURCE)
                    s, stable = create_fork(*s.args, old=s), False
                    continue
                else:
                    # This prevents an infinite loop if the fork keeps dying.
                    emit(f"Unstable crown, aborting. Check {__file__} for errors.")
                    sys.exit(1)
            if not stable:
                emit(f"Stabilized {s.pid=}.")
                SOURCE = fread(__file__, decode='utf-8')
            stable = True

# Get constant values from the source code even if it's been mutated.
def get_const(name: t.LiteralString) -> str:
    global SOURCE
    for line in SOURCE.splitlines():
        if line.startswith(f'{name} = '):
            return line.split(' = ')[1].strip("'")
    return None
            
def smoke_test():
    emit('Hello world!')
    try:
        while True:
            time.sleep(1)
            emit('Still alive.')
    except KeyboardInterrupt:
        emit('Goodbye world!')
        sys.exit(0)

def another_function():
    emit('Another function.')
    sys.exit(1)
        
    
# RUNLEVEL will only be greater than 0 when qaczar.py is executing.
if __name__ == "__main__":
    emit('----------------------------------------')
    try:    
        # We copy ourselves and put the crown on the copy.
        SOURCE = fread(__file__, decode='utf-8')
        if RUNLEVEL == 1:
            watch_over(create_fork(__file__))
        elif RUNLEVEL == 2:
            main_function = globals().get(MAIN, None)
            if main_function is None:
                emit(f"Invalid function {MAIN=}. DNR.")
                sys.exit(0)
            main_function()
            
    except KeyboardInterrupt:
        emit(f"Keyboard interrupt {RUNLEVEL=}"); raise
    except RuntimeError:
        emit(f'Crown failure, unable to start.'); raise
