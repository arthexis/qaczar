#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import time
import sqlite3
import urllib.request
import bottle


HOST = os.environ.get('HOST', 'localhost')
PORT = int(os.environ.get('PORT', 8080))

runlevel = 0
log_history = []

# Log a message to the console and to the log file.
def log(text):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    print(ts + ' - ' + text)
    log_history.append((ts, text))


# Calculate the uptime.
epoch = os.path.getmtime(__file__)
def get_uptime():
    return time.time() - epoch


# --- EXTERNAL DATA ACCESS ---

# Download a file by url and return the bytes.
def fetch_file(url):
    log('Downloading file: ' + url)
    try:
        with urllib.request.urlopen(url) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        log('Error downloading file: ' + url)
        log(str(e))


# Commit to git.
def git_commit(message):
    log('Committing to git.')
    os.system(f'git add . && git commit -m "{message}" && git push')


# --- DATABASE FUNCTIONS ---

# Insert a string of text a specified table.
# If the table doesn't exist, create it.
# Each row has a timestamp and a string of text.
def store_text(table, text):
    c = db.cursor()
    c.execute(f'CREATE TABLE IF NOT EXISTS {table} (id INTEGER PRIMARY KEY, ts TEXT, text TEXT)')
    c.execute(f'INSERT INTO {table} (ts, text) VALUES (?, ?)', (time.time(), text))
    db.commit()


# Get the latest text stored in the database table. Log the timestamp.
def get_latest_text(table):
    c = db.cursor()
    try:
        c.execute(f'SELECT ts, text FROM {table} ORDER BY id DESC LIMIT 1')
        ts, text = c.fetchone()
    except sqlite3.OperationalError:
        log(f'No data in table {table}.')
        return ''
    # Format the timestamp.
    ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(ts)))
    log(f'Last {table} from {ts} ({len(text)} bytes)')
    return text


# Get all the text from a table in time order.
def get_text(table, reverse=False, limit=10):
    log(f'Get {table} from db.')
    c = db.cursor()
    # Format fs as follows: Request #ID at TIMESTAMP
    try:
        c.execute(f'SELECT id, ts, text FROM {table} ORDER BY id {"DESC" if reverse else ""} LIMIT {limit}')
    except sqlite3.OperationalError:
        log(f'No data in table {table}.')
        return []
    for row in c.fetchall():
        id, ts, text = row
        ts = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(ts)))
        yield f'{table} #{id} at {ts}', text


# Insert a backup of the running script into the database.
def backup_script():
    with open(__file__, 'r') as f:
        store_text('source', f.read())
    log('Source backed to db.')


# Get a list of all the tables in the database.
def get_tables():
    c = db.cursor()
    c.execute('SELECT name FROM sqlite_master WHERE type="table"')
    return [t[0] for t in c.fetchall()]


# Drop a table from the database.
def drop_table(table):
    c = db.cursor()
    c.execute(f'DROP TABLE IF EXISTS {table}')
    db.commit()
    log(f'Dropped table {table}.')


# --- WATCHER FORK ---

# General functions should be defined before this point if
# they are need to be user by the watcher process.

db = sqlite3.connect('db.sqlite')
if __name__ == "__main__":
    log('Connecting to sqlite database.')
    runlevel = 1
    if len(sys.argv) == 1:
        log("Preparing watch fork.")
        import subprocess
        import atexit
        while True:
            server = subprocess.Popen([sys.executable, __file__, "--server"])
            savepoint = time.time()
            atexit.register(server.terminate)
            mtime = os.path.getmtime(__file__) 
            while True: 
                time.sleep(1)
                if os.path.getmtime(__file__) != mtime:
                    log("Change detected. Restarting server.")
                    break
                if server.poll() is not None:  # Server has crashed.
                    log("Server terminated unexpectedly. Reverting source.")
                    original = get_latest_text('source')
                    if not original:
                        log("No source backup found. Exiting.")
                        sys.exit(1)
                    with open(__file__, 'w') as f:
                        f.write(original)
                    break
            log("Stopping server.")
            server.terminate()
            server.wait()


# --- VIEW COMPONENTS ---

# Convert an URL into an image tag.
def url_to_img(url, alt=''):
    return f'<img src="{url}" alt="{alt}">'


# Initialize some application state on startup.
def first_load():
    global runlevel
    backup_script()
    log(f'First load in {time.time() - epoch}s')
    runlevel = 3


# Process an incoming request.
def process_request(request):
    command, *params = request.split()
    if command == 'todo':
        store_text('todo', ' '.join(params))
        return 'Todo stored.'
    if command == 'drop':
        if not params:
            return 'No table specified.'
        drop_table(params[0])
        return 'Table dropped.'
    log(f'Unknown command: {command}')


# Generate a checklist of all the todos.
def get_todos():
    for title, text in get_text('todo'):
        yield f'<li><input type="checkbox" id="{title}"><label for="{title}">{text}</label></li>'

# --- STYLES ---

CSS = '''
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


# --- BOTTLE ROUTES ---

# Return the server uptime (since the script was last modified).
@bottle.route('/api/uptime')
def view_uptime():
    return str(get_uptime())


# Process a request as text and redirect to the main page.
@bottle.route('/api/request', method='POST')
def view_request_post():
    request = bottle.request.forms.get('request')
    if request:
        store_text('request', request.strip())
        result = process_request(request)
        if result:
            store_text('result', result)
            log(f'Result: {result}')
    bottle.redirect('/')


# Render the main view (index)
@bottle.route('/')
def view_index():
    if runlevel == 2:
        first_load()
    # Format current time as a string.
    current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    table = bottle.request.query.get('table', 'request')
    main_content = get_text(table, reverse=True)
    todos = get_todos()
    tables = get_tables()
    uptime = get_uptime()
    return bottle.template('''
        <style>{{css}}</style>

        <div class="left">
            <table><tr>
                % for table in tables:
                    <th><a href="/?table={{table}}">{{table}}</a></th>
                % end
            </tr></table>
            <table>
                % for context, line in main_content:
                <tr title="{{context}}"><td>{{! line}}</td></tr>
                % end
            </table>
        </div>
        
        <div class="right">
            <p>Uptime: {{ uptime }} </p>
            <p>Last refresh: {{ current_time }} </p>
            <form action="/api/request" method="post">
                <textarea name="request" rows="10" cols="50"></textarea><br />
                <input type="submit" value="Submit (Ctrl+Enter)" />
                <ul class="todos">
                    % for todo in todos:
                        {{! todo}}
                    % end
                </ul>
            </form>
            <table>
                <thead><tr><th>Time</th><th>Message</th></tr></thead>
                % for t, m in reversed(log_history):
                    <tr><td>{{t}}</td><td>{{m}}</td></tr>
                % end
            </table>
        </div>    

        <script>
            window.scrollTo(0, document.body.scrollHeight);
            document.querySelector('textarea').focus();
            document.querySelector('textarea').addEventListener('keydown', function(e) {
                if (e.keyCode == 13 && e.ctrlKey) {
                    e.preventDefault();
                    document.querySelector('form').submit();
                }
            });
            setInterval(function() {
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '/api/uptime');
                xhr.onload = function() {
                    if (xhr.status == 200) {
                        if (xhr.responseText < {{ uptime }}) location.reload();
                        else document.querySelector('p').innerHTML = 'Uptime: ' + xhr.responseText;
                    }
                };
                xhr.send();
            }, 1000);
        </script>
    
    ''', **locals(), log_history=log_history, css=CSS)
    

# Start the bottle server for user requests.
if __name__ == '__main__':
    runlevel = 2
    if len(sys.argv) == 2 and sys.argv[1] == '--server':
        log('Starting bottle server.')
        bottle.run(host=HOST, port=PORT)

