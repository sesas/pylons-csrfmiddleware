"""
Cross Site Request Forgery Middleware.

This is a middleware that implements protection against request
forgeries from other sites.

This is a Pylons port of Luke Plant's django version.

"""
import re
import itertools
import logging

from webob import Request
from webob.exc import HTTPForbidden

_ERROR_MSG = 'Cross Site Request Forgery detected. Request aborted.'

_POST_FORM_RE = \
    re.compile(r'(<form\W[^>]*\bmethod=(\'|"|)POST(\'|"|)\b[^>]*>)', re.IGNORECASE)
    
_HTML_TYPES = ('text/html', 'application/xhtml+xml')    

_CSRF_COOKIE_NAME = 'csrftoken'

_CSRF_HEADER_NAME = 'X-CSRF-Token'

logger = logging.getLogger('csrfmiddleware')

class CsrfMiddleware(object):
    """Middleware that adds protection against Cross Site
    Request Forgeries by adding hidden form fields to POST forms and 
    checking requests for the correct value. It expects beaker to be upstream
    to insert the session into the environ 
    """

    def __init__(self, app, config):
        self.app = app
        self.unprotected_path = config.get('csrf.unprotected_path')

    def __call__(self, environ, start_response):
        request = Request(environ)
        session = environ['beaker.session']
        session.save()

        csrf_token = session.id

        # Check headers first for CSRF token
        if _CSRF_HEADER_NAME in request.headers:
            if request.headers.get(_CSRF_HEADER_NAME) == csrf_token:
                # Valid request. Don't do any checking
                logger.debug('CSRF header checking passed.')
                resp = request.get_response(self.app)

        elif (request.referer or '').startswith(request.host_url):
            # Valid referer
            logger.debug('CSRF: Referer header check passed.')
            resp = request.get_response(self.app)

        elif request.method == 'POST':
            # check to see if we want to process the post at all
            if (self.unprotected_path is not None
                and request.path_info.startswith(self.unprotected_path)):
                resp = request.get_response(self.app)
                return resp(environ, start_response)

            # check incoming token
            try:
                request_csrf_token = request.POST['csrfmiddlewaretoken']
                if request_csrf_token != csrf_token:
                    resp = HTTPForbidden(_ERROR_MSG)
                else:
                    resp = request.get_response(self.app)
            except KeyError:
                resp = HTTPForbidden(_ERROR_MSG)
        # if we're a get, we don't do any checking
        else:
            resp = request.get_response(self.app)

        if resp.status_int != 200:
            return resp(environ, start_response)

        if resp.content_type.split(';')[0] in _HTML_TYPES:
            # ensure we don't add the 'id' attribute twice (HTML validity)
            idattributes = itertools.chain(('id="csrfmiddlewaretoken"',), 
                                            itertools.repeat(''))
            def add_csrf_field(match):
                """Returns the matched <form> tag plus the added <input> element"""
                return match.group() + '<div style="display:none;">' + \
                '<input type="hidden" ' + idattributes.next() + \
                ' name="csrfmiddlewaretoken" value="' + csrf_token + \
                '" /></div>'

            # Modify any POST forms and fix content-length
            resp.body = _POST_FORM_RE.sub(add_csrf_field, resp.body)

        # Set csrf cookie anyway, cause all responses need it.
        resp.set_cookie(_CSRF_COOKIE_NAME, csrf_token)

        return resp(environ, start_response)


def make_csrf_filter(global_conf, **kw):
    """this is suitable for the paste filter entry point"""
    def filter(app):
        return CsrfMiddleware(app, kw)
    return filter

def make_csrf_filter_app(app, global_conf, **kw):
    """this is suitable for the paste filter-app entry point"""
    return CsrfMiddleware(app, kw)
