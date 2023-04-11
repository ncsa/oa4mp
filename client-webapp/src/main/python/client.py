import time

__author__ = 'jeff gaynor'

import re, hashlib, random
import logging
import cgi
from oa4mp import OA4MPService, Config, FileStore
from  urllib import unquote
from string import strip

CERT_REQUEST_ID="oa4mp_client_req_id" # As per spec.
CONFIG_FILE_KEY = "oa4mp.config.file"
CONFIG_NAME_KEY="oa4mp.config.name"

def index(environ, start_response):
    action = environ['oa4mp.config.path'] + '/startRequest'
    logit(environ, "landed on index page.")
    start_response('200 OK', [('Content-Type', 'text/html')])
    body = '<html><body><H1>A Sample Delegation Portal</h1>'
    body = body + '<form name="input" action="' + action + '" method="get" enctype="application/x-www-form-urlencoded">'
    body = body + 'Click to request a credential<br><br><input type="submit" value="start request" /></form>'
    body = body + '</body></html>'
    return body


def not_found(environ, start_response):
    """Called if no URL matches."""
    logit(environ, "NOT FOUND -- request for a non-existent endpoint returns a 404 error")
    start_response('404 NOT FOUND', [('Content-Type', 'text/plain')])
    return ['Not Found']

def failure(environ, start_response):
    """
    Called in case of failures and also given as a redirect from the server if the user, say, cancels and
    operation.
    """
    start_response('200 OK', [('Content-Type', 'text/html')])
    logit(environ, "In failure call")
    action = environ['oa4mp.config.path'] + '/startRequest' # for button to get back to someplace useful
    body = '<html><body><H1>Uh-oh...!</h1><p>There was a problem getting your certificate...</p>'
    body = body + '<form name="input" action="' + action + '" method="get" enctype="application/x-www-form-urlencoded">'
    body = body + 'Click return to the site<br><br><input type="submit" value="return" /></form>'
    body = body + '</body></html>'
    return body

# Wrapper that has causes asset store cleanup after each callback.
# This is not optimal, but probably the easiest way to get
# WSGI to actually do something like this.

def callback(environ, start_response):
     try:
        return _callback(environ, start_response)
     finally:
        configFile = environ[CONFIG_FILE_KEY]
        configName = environ[CONFIG_NAME_KEY]
        config = Config(configFile, configName)
        cfg = config.read()
        store = FileStore(cfg=cfg)
        # Perform required cleanup task. Given the difficulty of controlling threads
        # in WSGI having an invocation at the end of the call back is an acceptable trade-off
        # This might have to be improved later...
        store.cleanup()


def _callback(environ, start_response):
    """
    The callback, to wit, this will take the oauth token returned by the server, swap it for an
     access token then get the cert, storing it as an asset.
    """
    # Standard canonical way to interpret the request values is to run the wsgi environment
    # through the cgi module
    form = cgi.FieldStorage(fp=environ['wsgi.input'],
                            environ=environ,
                            keep_blank_values=1)

    # Get data from fields
    token = unquote(form.getvalue('oauth_token', None))
    v  = unquote(form.getvalue('oauth_verifier', None))
    configFile = environ[CONFIG_FILE_KEY]
    configName = environ[CONFIG_NAME_KEY]
    logging.info('using cfg file=' + environ['oa4mp.config.file'] + ', name=' + environ['oa4mp.config.name'])

    config = Config(configFile, configName)
    cfg = config.read()
    logit(environ, "skin=" + cfg["skin"])
    id = None
    fileStore = FileStore(cfg)

    if environ.has_key('HTTP_COOKIE'):
        for cookie in map(strip, re.split(';', environ['HTTP_COOKIE'])):
             try:
                 (key, value ) = re.split('=', cookie)
                 if key == CERT_REQUEST_ID:
                     id = value
                     if fileStore.get(id) != None:
                         # jump out once you find the first one that works.
                         # If they have cruft in their browser
                         # such as from repeated failed earlier attempts,
                         # we can't figure which is the right one
                         break
                     else:
                         logit(environ,'No asset found for id=' + id + ', skipping it.')

             except ValueError, e:
                 logging.exception('Benign error parsing cookie=' + cookie + '. Skipping...')

    # In this case, no cookie was found to identify that a request was made.
    if id is None:
        logit(environ, 'No id found at all.')
        return failure(environ, start_response)

    logit(environ, "in callback for id=" + id)
    oa4mp = OA4MPService()
    try:
        username, cert = oa4mp.getCert(id, cfg, token, v)
    except:
        logit(environ, 'Could not find the cert from the id')
        return failure(environ,start_response)

    action = environ['oa4mp.config.path']

    headers = [('Content-Type', 'text/html'),
       ('Set-Cookie', CERT_REQUEST_ID + '= ; Expires=Thursday, 1-Jan-1970 00:01:00 GMT;')] # zero its value out
    # set the cookie to expire in the past so the browser will try to clean it up.
    # Browsers have the choice of cleanup. Setting the expired date strongly suggests
    # they should get rid of it.

    start_response('200 OK', headers)
    body = '<html><body><H1>Success!</h1><p>Here is what was returned</p>'
    body=body + '<br><br>username =' + username
    body = body+ '<br><br>Certificate:<br><br><pre>' + cert + '</pre><br><hr>'
    body = body + '<form name="input" action="' + action + '" method="get" enctype="application/x-www-form-urlencoded">'
    body = body + 'Click to return to the main site.<br><br><input type="submit" value="return" /></form><br><hr>'
    body = body + '</body></html>'
    logit(environ, "finished with callback")
    return body

def startRequest(environ, start_response):
    """
    Start the cert request cycle. This will create a random that is set in a cookie
    which will be later read so that the state can be managed (state meaning an
    asset in the asset store). If successful, this returns a redirect to the main
    site.
    """
    # get the name from the url if it was specified there.
    #print >> environ['wsgi.errors'], "cfg file = " + environ['oa4mp.config.file']
    logit(environ, "starting new request")

    oa4mp = OA4MPService()
    configFile = environ['oa4mp.config.file']
    configName = environ['oa4mp.config.name']
    try:
       config = Config(configFile, configName)
       cfg = config.read()
    except:
        logit(environ, 'Error reading configuration')
        return failure(environ, start_response)
    # print >> environ['wsgi.errors'], "service uri = " + cfg['serviceUri']
    id = 'oa4mp-' + hashlib.sha1(str(random.random()) + str(random.random())).hexdigest()
    logit(environ, "created id = " + id)
    try:
        key, redirectUri = oa4mp.requestCert(id, cfg)
    except:
        logit(environ,'Error in request Cert for id=' + id)
        return failure(environ,start_response)

    headers = [('Content-Type', 'text/html'),
       ('Set-Cookie', CERT_REQUEST_ID + '=' + id + ";"),# cookie -- don't set path since API for reading doesn't support it!!!
       ('Location', redirectUri)]# Location header + 302 status code = redirect
    logit(environ, "set cookie");#    foo = [('Content-Type', 'text/html'),
    # Status of 302 required for redirect.
    start_response('302 FOUND', headers)

    # If the 302 redirect works as it should, then the body will never be seen. In case something happens
    # the user should at least have a chance to continue manually.
    body=  '<html><body>Please follow this <a href="'
    body = body + str(redirectUri) #or the body is converted to unicode and cannot be used as a response.
    body = body + '">link</a>!</body></html>\n'
    logit(environ, "done with initial request, redirect uri = " + str(redirectUri))
    return body

# Primitive logging, but works across the board. Replace if you need something more clever.
# Everything goes to the error file so designated by your setup.
def logit(environ, x):
    print >> environ['wsgi.errors'], str(x)


def success(environ, start_response):
    """
    Very primitive success page.
    """
    logit(environ, "Success page requested")
    return "<html><body><h2>Success!!!</h2></body></html>"

urls = [
    (r"startRequest", startRequest),
    (r"success", success),
    (r"failure", failure),
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
    # If running in the debugger, uncomment these three lines to fake an Apache server.
    # FIXME!!
    #environ[CONFIG_FILE_KEY]='/home/ncsa/dev/csd/config/oa4mp-clients.xml'
    #environ[CONFIG_NAME_KEY]='python-cilogon2'
    #environ['oa4mp.config.path']='client'
    path = environ.get('PATH_INFO', '').lstrip('/')
    for regex, callback in urls:
        match = re.search(regex, path)
        if match is not None:
            environ['myapp.url_args'] = match.groups()
            return callback(environ, start_response)
    return not_found(environ, start_response)

# Simple entry point for running a debug server. Generally only for development since
# any OA4MP server will refuse to connect to this without SSL.
if __name__ == '__main__':
    from wsgiref.simple_server import make_server
    srv = make_server('localhost', 44443, application)
    srv.serve_forever()
