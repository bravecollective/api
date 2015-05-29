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

        # We allow responses 1s from the future to account for slight clock skew.
        if datetime.utcnow() - date < timedelta(seconds=-1):
            log.warning("Received a request from the future; please check this systems time for validity.")
            raise BadSignatureError

        # Raises an exception on failure.
        try:
            self.public.verify(
                    unhexlify(response.headers['X-Signature'].encode('utf-8')),
                    canon.encode('utf-8'),
                    hashfunc=sha256
                )
        except BadSignatureError:
            # Try verifying again with the time adjusted by one second.
            date = date - timedelta(seconds=1)
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

class Permission(object):
    """This is a static class intended to provide applications with an implementation of the Core permission
    wildcard checking. Applications are free to use their own implementation of this, but *MUST* provide the
    exact same results if they do."""

    GRANT_WILDCARD = '*'

    @staticmethod
    def grants_permission(wildcard_perm, granted_perm):
        """This is used to see if a permission grants access to a permission which is not in the Core database.
            For instance, when evaluating whether a WildcardPermission grants access to a run-time permission."""
        # Splits both this permission's id and the permission being checked.
        wild_segments = wildcard_perm.split('.')
        perm_segments = granted_perm.split('.')

        # If the wildcard permission has more segments than the permission we're matching against, it can't provide access
        # to that permission.
        if len(wild_segments) > len(perm_segments):
            return False

        # If the permission we're checking against is longer than the wildcard permission (this permission), then this
        # permission must end in a wildcard for it to grant the checked permission.
        if len(wild_segments) < len(perm_segments):
            if Permission.GRANT_WILDCARD != wild_segments[-1]:
                return False

        # Loops through each segment of the wildcard_perm and permission. 'core.example.*.test.*' would have
        # segments of 'core', 'example', '*', 'test', and '*' in that order.
        for (w_seg, perm_seg) in zip(wild_segments, perm_segments):
            # We loop through looking for something wrong, if there's nothing wrong then we return True.

            # This index is a wildcard, so we skip checks
            if w_seg == Permission.GRANT_WILDCARD:
                continue

            # If this wild segment doesn't match the corresponding segment in the permission, this permission
            # doesn't match, and we return False
            if w_seg != perm_seg:
                return False

        return True

    @staticmethod
    def has_any_permission(perm, wild_perm):
        if Permission.grants_permission(wild_perm, perm):
            return True
        return False

    @staticmethod
    def set_has_any_permission(perms, checked_perm):
        permissions = []
        for p in perms:
            if Permission.has_any_permission(p, checked_perm):
                permissions.append(p)
        return permissions

    @staticmethod
    def set_grants_permission(perms, granted_perm):
        """Loops through a set of permissions and checks if any of them grants permission for granted_perm. Ideal for
            checking if a character/user has the ability to conduct an action"""

        for p in perms:
            if Permission.grants_permission(p, granted_perm):
                return True

        return False
