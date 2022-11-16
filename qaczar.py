import os
import sys
import time

# Automatic server restart on script change.
if len(sys.argv) == 1:
    print("Starting in watch mode.")
    import subprocess
    import atexit
    cmd = [sys.executable, __file__, "--server"]
    server = subprocess.Popen(cmd)
    atexit.register(server.terminate)
    mtime = os.path.getmtime(__file__)    
    with open(__file__, 'r') as f:
        # TODO: After a change has been accepted, reset original.
        original = f.read()
    while True: 
        time.sleep(1)
        if os.path.getmtime(__file__) != mtime:
            print("Change detected. Restarting server.")
            server.terminate()
            server.wait()
            mtime = os.path.getmtime(__file__)
            server = subprocess.Popen(cmd)
        elif server.poll() is not None:
            print("Server terminated.")
            with open(__file__, 'r') as f:
                text = f.read()
            if text != original:
                print("Script changed. Reverting.")
                with open(__file__, 'w') as f:
                    f.write(original)
            print("Restarting server.")
            server = subprocess.Popen(cmd)


import types
import urllib.request

HOST = 'localhost'
PORT = 8080
EPOCH = os.path.getmtime(__file__)


# Download a python script from the Internet and load it as a module.
def fetch_module(name, url):
    with urllib.request.urlopen(url) as r:
        script = r.read().decode("utf-8")
    module = types.ModuleType(name)
    module.__file__ = url  # Expected by some modules (bottle).
    exec(script, module.__dict__)
    return module


bottle = fetch_module('bottle', 'https://raw.githubusercontent.com/bottlepy/bottle/master/bottle.py')


# Override 404 error handler, or bottle renders an ImportError.
@bottle.error(404)
def view_not_found(error):
    return error.body


# Return the text of the currently executing python script.
@bottle.route('/qaczar.py')
def view_self():
    with open(__file__, 'r') as f:
        text = f.read()
    return text


# Return the server uptime (since the script was last modified).
@bottle.route('/uptime')
def view_uptime():
    return str(time.time() - EPOCH)


# Get all the import statements from the script.
def get_imports():
    with open(__file__, 'r') as f:
        text = f.read()
    return [line for line in text.splitlines() if line.startswith('import ')]


if __name__ == '__main__':
    bottle.run(host=HOST, port=PORT)
    
