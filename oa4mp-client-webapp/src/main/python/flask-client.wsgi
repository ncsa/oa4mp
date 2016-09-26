import re

__author__ = 'ncsa'

from flask import Flask

app = Flask(__name__)

@app.route('/foo/startRequest')
def startRequest():
    return 'request started'

@app.route('/foo/callback')
def callback():
    return 'callback'

@app.route('/foo/callback')
def index():
    return 'index'

@app.route('/foo')
def success():
    return 'success'

urls = [
    (r"startRequest", startRequest),
    (r"success", success),
    (r"index", index),
    (r"ready", callback),
    (r"^$", index),

]

def application(environ, start_response):
    """
    The main WSGI application. Dispatch the current request to
    the functions from above and store the regular expression
    captures in the WSGI environment.

    If nothing matches call the `not_found` function.
    """
    #Note: PATH_INFO is a standard WSGI environment value for the path in the request URL.
    # If running in the debugger, uncomment these two lines to fake an Apache server.
    # FIXME!!
    #environ[CONFIG_FILE_KEY]='/home/ncsa/dev/csd/config/oa4mp-clients.xml'
    #environ[CONFIG_NAME_KEY]='python-cilogon2'
    path = environ.get('PATH_INFO', '').lstrip('/')
    for regex, callback in urls:
        match = re.search(regex, path)
        if match is not None:
            environ['myapp.url_args'] = match.groups()
            return callback(environ, start_response)
    return index(environ, start_response)

if __name__ == '__main__':
    app.run()