# encoding: utf-8

from __future__ import unicode_literals

import requests
import sys

from binascii import hexlify, unhexlify
from datetime import datetime
from hashlib import sha256
from webob import Response
from marrow.util.bunch import Bunch
from requests.auth import AuthBase
from ecdsa.keys import BadSignatureError
from datetime import datetime, timedelta


log = __import__('logging').getLogger(__name__)


if sys.version_info[0] >= 3:
    unistr = str
else:
    unistr = unicode


def bunchify(data, name=None):
    if isinstance(data, Bunch):
        return data
    
    if isinstance(data, list):
        return [bunchify(i) for i in data]
    
    if isinstance(data, dict):
        if hasattr(data, 'iteritems'):
            bunch_data = {k: bunchify(v, k) for k, v in data.iteritems()}
        else:
            bunch_data = {k: bunchify(v, k) for k, v in data.items()}
        return Bunch(bunch_data)
    
    return data


class SignedAuth(AuthBase):
    def __init__(self, identity, private, public):
        self.identity = identity
        self.private = private
        self.public = public
    
    def __call__(self, request):
        request.headers['Date'] = Response(date=datetime.utcnow()).headers['Date']
        request.headers['X-Service'] = self.identity
        
        if request.body is None:
            request.body = ''
        
        canon = "{r.headers[date]}\n{r.url}\n{r.body}".format(r=request).\
                encode('utf-8')
        log.debug("Canonical request:\n\n\"{0}\"".format(canon))
        request.headers['X-Signature'] = hexlify(self.private.sign(canon))
        
        request.register_hook('response', self.validate)
        
        return request
    
    def validate(self, response, *args, **kw):
        if response.status_code != requests.codes.ok:
            log.debug("Skipping validation of non-200 response.")
            return
        
        log.info("Validating %s request signature: %s", self.identity, response.headers['X-Signature'])
        canon = "{ident}\n{r.headers[Date]}\n{r.url}\n{r.text}".format(ident=self.identity, r=response)
        log.debug("Canonical data:\n%r", canon)

        date = datetime.strptime(response.headers['Date'], '%a, %d %b %Y %H:%M:%S GMT')
        if datetime.utcnow() - date > timedelta(seconds=15):
            log.warning("Received response that is over 15 seconds old, rejecting.")
            raise BadSignatureError

        if datetime.utcnow() - date < timedelta(seconds=0):
            log.warning("Received a request from the future; please check this systems time for validity.")
            raise BadSignatureError
        
        date = date - timedelta(seconds=1)

        # Raises an exception on failure.
        try:
            self.public.verify(
                    unhexlify(response.headers['X-Signature'].encode('utf-8')),
                    canon.encode('utf-8'),
                    hashfunc=sha256
                )
        except BadSignatureError:
            canon = "{ident}\n{date}\n{r.url}\n{r.text}".format(ident=self.identity, r=response, date=date.strftime('%a, %d %b %Y %H:%M:%S GMT'))
            self.public.verify(
                    unhexlify(response.headers['X-Signature'].encode('utf-8')),
                    canon.encode('utf-8'),
                    hashfunc=sha256
                )


class API(object):
    __slots__ = ('endpoint', 'identity', 'private', 'public', 'pool')
    
    def __init__(self, endpoint, identity, private, public, pool=None):
        self.endpoint = unistr(endpoint)
        self.identity = identity
        self.private = private
        self.public = public
        
        if not pool:
            self.pool = requests.Session()
        else:
            self.pool = pool
    
    def __getattr__(self, name):
        return API(
                '{0}/{1}'.format(self.endpoint, name),
                self.identity,
                self.private,
                self.public,
                self.pool
            )
    
    def __call__(self, *args, **kwargs):
        result = self.pool.post(
                self.endpoint + ( ('/' + '/'.join(unistr(arg) for arg in args)) if args else '' ),
                data = kwargs,
                auth = SignedAuth(self.identity, self.private, self.public)
            )
        
        if not result.status_code == requests.codes.ok:
            return None
        
        return bunchify(result.json())
