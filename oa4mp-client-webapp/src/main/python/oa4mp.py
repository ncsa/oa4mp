import httplib2
import urllib

__author__ = 'jeff'

from oauth2 import Client
from oauth2 import Request
from oauth2 import Consumer
from oauth2 import escape
from oauth2 import generate_nonce
from oauth2 import SignatureMethod
from oauth2 import generate_timestamp
import subprocess
from base64 import b64encode


# some general constants
ID_TAG='id'
SERVICE_URI_TAG='serviceUri'
AUTHORIZE_URI_TAG='authorizeUri'
CALLBACK_URI_TAG = 'callbackUri'
LIFETIME_TAG='lifetime'
PUBLIC_KEY_FILE_TAG='publicKeyFile'
PRIVATE_KEY_FILE_TAG='privateKeyFile'
FILE_STORE_TAG='fileStore'
FILE_STORE_PATH_TAG='path' #use this in the cfg dictionary.
ENABLE_ASSET_CLEANUP_TAG='enableAssetCleanup'
MAX_ASSET_LIFETIME_TAG='maxAssetLifetime'
CLIENT_TAG = 'client' # the name of the tag in the xml file denoting client configurations
OAUTH_CONSUMER_KEY='oauth_consumer_key' # as per OAuth spec.
SKIN_TAG="skin" # for the skin to use, if present
CERT_REQUEST_CONFIG_FILE='certReqConfig'

# What follows are the keys used in the asset dictionary.
USERNAME_KEY='username'
CERTS_KEY='certs'
TIMESTAMP_KEY='timestamp'
PRIVATE_KEY_KEY='privateKey'
REDIRECT_URI_KEY='redirectUri'
# A customized rsa sha1 signature algorithm. Must be created by passing it a
# certificate request.

class SignatureMethod_RSA_SHA1(SignatureMethod):
    def __init__(self, certReq=None, privateKeyFile=None):
        self.certReq = certReq
        self.privateKeyFile = privateKeyFile
    name = 'RSA-SHA1'

    def signing_base(self, request, consumer, token):
        if not hasattr(request, 'normalized_url') or request.normalized_url is None:
            raise ValueError("Base URL for request is not set.")

        sig = (
            escape(request.method),
            escape(request.normalized_url),
            escape(request.get_normalized_parameters()),
            )

        key = '%s&' % escape(consumer.secret)
        if token:
            key += escape(token.secret)
        raw = '&'.join(sig)
        return key, raw

    def sign(self, request, consumer, token):
        """Builds the base signature string."""
        key, raw = self.signing_base(request, consumer, token)
        opensslproc = subprocess.Popen(['openssl', 'dgst', '-sha1', '-sign',
                                        self.privateKeyFile,
                                        '-binary'], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        opensslproc.stdin.write(raw)
        opensslproc.stdin.close()
        computedSig = b64encode(opensslproc.stdout.read()).replace('\n', '')
        return computedSig

class OA4MPClient(Client):
    def request(self, uri, method="GET", body='', headers=None,
                redirections=httplib2.DEFAULT_MAX_REDIRECTS, connection_type=None,
                parameters=None):

        if not isinstance(headers, dict):
            headers = {}

        req = Request.from_consumer_and_token(self.consumer,
            token=self.token, http_method=method, http_url=uri,
            parameters=parameters, body=body, is_form_encoded=True)

        req.sign_request(self.method, self.consumer, self.token)
        uri = req.to_url()
        return httplib2.Http.request(self, uri, method=method, body=body,
            headers=headers, redirections=redirections,
            connection_type=connection_type)

import time
class OA4MPService(object):

    def getCert(self, id, cfg, token, verifier):
        oauthKey = cfg[OAUTH_CONSUMER_KEY]
        params = {'oauth_nonce' : generate_nonce(),
                  'oauth_token' : token,
                  'oauth_verifier' : verifier,
                  'oauth_timestamp' : generate_timestamp(),
                  'oauth_signature_method' : 'RSA-SHA1',
                  'oauth_consumer_key' :  oauthKey,
                  'oauth_version' : '1.0'
        }

        consumer = Consumer(oauthKey,'')
        rsa_sha1 = SignatureMethod_RSA_SHA1(privateKeyFile=cfg[PRIVATE_KEY_FILE_TAG])

        client = OA4MPClient(consumer=consumer)
        client.set_signature_method(rsa_sha1)
        response,content = client.request(cfg[SERVICE_URI_TAG] + '/token', parameters=params)
        tokens = content.split('&')
        access_token = urllib.unquote(tokens[0].split('=')[1])
        params = {'oauth_nonce' : generate_nonce(),
                  'oauth_token' : access_token,
                  'oauth_timestamp' : generate_timestamp(),
                  'oauth_signature_method' : 'RSA-SHA1',
                  'oauth_consumer_key' :  oauthKey,
                  'oauth_version' : '1.0'
        }

        # we now have the token and the secret.
        consumer = Consumer(oauthKey,'')
        rsa_sha1 = SignatureMethod_RSA_SHA1(privateKeyFile=cfg[PRIVATE_KEY_FILE_TAG])

        client = OA4MPClient(consumer=consumer)
        client.set_signature_method(rsa_sha1)
        response,content = client.request(cfg[SERVICE_URI_TAG] + '/getcert', parameters=params)
        tokens = content.split('\n')
        username = urllib.unquote(tokens[0].split('=')[1])
        tokens = tokens[1:]
        certs='\n'.join(tokens)
        fileStore = FileStore(cfg)
        asset = fileStore.get(id)
        asset[USERNAME_KEY] = username
        asset[CERTS_KEY] = certs
        fileStore.put(id, asset)
        return username, certs

    def requestCert(self, id, cfg):
        END_RSA_PRIVATE_KEY = '-----END RSA PRIVATE KEY-----\n'
        END_ENCRYPTED_PRIVATE_KEY = '-----END ENCRYPTED PRIVATE KEY-----\n'
        opensslproc = subprocess.Popen(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-outform', 'DER', '-config' ,
                                        cfg[CERT_REQUEST_CONFIG_FILE]],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        opensslproc.stdin.close()
        data = opensslproc.stdout.readlines()

        pKeyPart = []
        certReqParts = []

        foundEndOfKey=False
        for x in data:
            if not foundEndOfKey:
                pKeyPart.append(x)
            else:
                certReqParts.append(x)

            if x == END_RSA_PRIVATE_KEY:
                foundEndOfKey = True
            if x == END_ENCRYPTED_PRIVATE_KEY:
                foundEndOfKey = True

        certReq = b''.join(certReqParts)
        computedSig = b64encode(b''.join(certReqParts))
        # Store it in the file store
        fileStore = FileStore(cfg)
        asset = {PRIVATE_KEY_KEY : ''.join(pKeyPart)}
        asset[TIMESTAMP_KEY] = time.time()
        asset[ID_TAG] = id ## keep it in the store just in case we need to recover this manually somehow.
        oauthKey = cfg[OAUTH_CONSUMER_KEY]
        params = {'oauth_nonce' : generate_nonce(),
                  'oauth_timestamp' : generate_timestamp(),
                  'oauth_signature_method' : 'RSA-SHA1',
                  'oauth_consumer_key' :  oauthKey,
                  'certlifetime' : '43200',
                  'oauth_version' : '1.0',
                  'oauth_callback' : cfg['callbackUri'],
                  'certreq' : computedSig}
        if cfg[SKIN_TAG] is not None:
            params[SKIN_TAG] = cfg[SKIN_TAG]

        consumer = Consumer(oauthKey,'')
        rsa_sha1 = SignatureMethod_RSA_SHA1(certReq = certReq, privateKeyFile=cfg[PRIVATE_KEY_FILE_TAG])

        client = OA4MPClient(consumer=consumer)
        client.set_signature_method(rsa_sha1)
        response,content = client.request(cfg[SERVICE_URI_TAG] + '/initiate', parameters=params)
        tokens = content.split('&')
        grant = urllib.unquote(tokens[0].split('=')[1])
        redirectUri = None
        # construct the URI as per spec if none is supplied, otherwise let the user over-ride it.
        if(cfg[AUTHORIZE_URI_TAG] is None):
            redirectUri = cfg[SERVICE_URI_TAG] + '/authorize?' + content.split('&')[0]
        else:
            redirectUri = cfg[AUTHORIZE_URI_TAG] + '?' + content.split('&')[0]
        redir = str(redirectUri)
        if cfg[SKIN_TAG] is not None:
            redir = redir + '&' + SKIN_TAG + '=' + cfg[SKIN_TAG]

        asset[REDIRECT_URI_KEY]=redir
        fileStore.put(id, asset)
        return  '\n'.join(pKeyPart), redir



import hashlib
import pickle
import os
# id is just a string that is a unique identifier (should be a url if you want interoperability with
# other stores).
# asset - a dictionary containing the private key, certificate, redirect uri and a timestamp.
class FileStore(object):
        # Eats a configuration dictionary so it can pull off information it needs.
        def __init__(self, cfg=None):
                self.cfg = cfg

        def get(self, id):
            try:
                targetFile=open(self.idToFile(id), 'r')
                asset = pickle.load(targetFile)
                targetFile.close()
                return asset
            except:
                return None # Probably need to improve this later?

        def put(self, id, asset):
            targetFile=open(self.idToFile(id), 'wr')
            pickle.dump(asset, targetFile)
            targetFile.close()
        # create a canonical unique name for the target file that will be compatible with any os.
        def idToFile(self, id):
            d = self.getPath()
            if not os.path.exists(d):
                os.makedirs(d)
            return d+  hashlib.sha1(id).hexdigest()

        def remove(self, id):
            os.remove(self.getPath())

        def getPath(self):
            return self.cfg[FILE_STORE_PATH_TAG]+'/assetStore/'

        def cleanup(self):
            d=self.getPath()

            for files in os.listdir(d):
                  fileName = d+files
                  # only process files.
                  if os.path.isfile(fileName):
                     # Remove dead ones, e.g. where the operation failed or was cancelled.
                     if os.path.getsize(fileName) == 0:
                       os.remove(fileName)
                     else:
                       try:
                           targetFile=open(fileName, 'r')
                           asset = pickle.load(targetFile)
                           targetFile.close()
                           t = asset[TIMESTAMP_KEY]
                           currentTime = time.time()
                           diff = currentTime - t
                           foo =  self.cfg[MAX_ASSET_LIFETIME_TAG] < diff
                           print 'current time=' + str(currentTime) + ", computed time=" + str(t) + ' diff = ' + str(diff)
                           print 'condition is ' + str( foo)
                           if  foo :
                               print 'removing file named ' + fileName
                               os.remove(fileName)
                       except:
                           # if for some strange reason the file doesn't parse as a valid asset, then just skip it.
                           pass



from xml.dom.minidom import parseString

# A class for parsing a configuration file and turning it into a dictionary of values.
class Config(object):
        def __init__(self, configFile, configName):
            self.configFile = configFile
            self.configName = configName

        def read(self):
            file = open(self.configFile,'r')
            #convert to string:

            data = file.read()
           # close file because we don't need it anymore:
            file.close()
            dom = parseString(data)
            #retrieve the first xml tag (<tag>data</tag>) that the parser finds with name tagName:
            # gets the first client
            clients = dom.getElementsByTagName(CLIENT_TAG)
            xmlTag = clients[0].toxml()
            # gets all config items. This should be a list

            targetConfig = None
            # find the named client configuration
            for client in clients:
               for (name, value) in client.attributes.items():
                  if name=='name' and value==self.configName:
                      targetConfig=client
                      break

            cfg = {OAUTH_CONSUMER_KEY : self.getValue(targetConfig, ID_TAG)}
            cfg[SERVICE_URI_TAG] = self.getValue(targetConfig, SERVICE_URI_TAG)
            cfg[SKIN_TAG] = self.getValue(targetConfig, SKIN_TAG)
            cfg[AUTHORIZE_URI_TAG] = self.getValue(targetConfig, AUTHORIZE_URI_TAG)
            cfg[LIFETIME_TAG] = self.getValue(targetConfig, LIFETIME_TAG)
            cfg[PUBLIC_KEY_FILE_TAG] = self.getValue(targetConfig, PUBLIC_KEY_FILE_TAG)
            cfg[PRIVATE_KEY_FILE_TAG] = self.getValue(targetConfig, PRIVATE_KEY_FILE_TAG)
            cfg[CALLBACK_URI_TAG] = self.getValue(targetConfig, CALLBACK_URI_TAG)
            cfg[FILE_STORE_PATH_TAG] = self.getAttribute(targetConfig, FILE_STORE_TAG, FILE_STORE_PATH_TAG)
            x  = self.getValue(targetConfig, ENABLE_ASSET_CLEANUP_TAG)
            if x is not None:
                cfg[ENABLE_ASSET_CLEANUP_TAG] = x.lower() == "true"
            x = self.getValue(targetConfig, MAX_ASSET_LIFETIME_TAG)
            if x is not None:
                cfg[MAX_ASSET_LIFETIME_TAG] = int(x)
            cfg[CERT_REQUEST_CONFIG_FILE] = self.getValue(targetConfig, CERT_REQUEST_CONFIG_FILE)
            return cfg

        def getValue(self, config, tag):
            rc = config.getElementsByTagName(tag)[0].firstChild.nodeValue
            return str(rc)

        def getAttribute(self, config, tag, attributeName):
            x = config.getElementsByTagName(tag)[0]
            rc = x.attributes[attributeName]
            return str(rc.firstChild.nodeValue)