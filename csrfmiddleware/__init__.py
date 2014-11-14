"""
Cross Site Request Forgery Middleware.

This is a middleware that implements protection against request
forgeries from other sites.

This is a Pylons port of Luke Plant's django version.

"""
import re
import hmac
import itertools
import logging

from webob import Request
from webob.exc import HTTPForbidden

REASON_NO_REFERER = "Referer checking failed - no Referer."
REASON_BAD_REFERER = "Referer checking failed - {} does not match {}."
REASON_NO_CSRF_COOKIE = "CSRF cookie not set."
REASON_BAD_TOKEN = "CSRF token missing or incorrect."

_ERROR_MSG = 'Cross Site Request Forgery detected. Request aborted.'

_POST_FORM_RE = \
    re.compile(r'(<form\W[^>]*\bmethod=(\'|"|)POST(\'|"|)\b[^>]*>)', re.IGNORECASE)
    
_HTML_TYPES = ('text/html', 'application/xhtml+xml')    

_CSRF_COOKIE_NAME = 'csrftoken'

_CSRF_HEADER_NAME = 'X-CSRF-Token'

_CSRF_HTML_NAME = 'csrfmiddlewaretoken'

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
        self.csrf_secret = config.get('csrf_secret', 'Some Secret!!!')

    def _accept(self, request, environ):
        # Set this attribute so that we know if CSRF has been checked.
        environ['csrf_processing_passed'] = True
        return request.get_response(self.app)

    def _reject(self, request, reason):
        logger.warning('Forbidden (%s): %s', reason, request.path,
                            extra={
                                'status_code': 403,
                                'request': request,
                                }
                       )
        return HTTPForbidden(_ERROR_MSG)

    def _get_basic_auth_headers(self, request):
        header = request.headers.get('Authenticate') or request.headers.get('Authorization')
        return header

    def is_secure(self, request):
        return request.scheme == 'https'

    def _check_request(self, request, correct_csrf_token, environ):

        incoming_csrf_cookie = request.cookies.get(_CSRF_COOKIE_NAME, '')

        # If basic auth credentials are provided, 
        # assume it's a valid user, and let later layers
        # check for the credentials validity, and respond 
        # accordingly.
        basic_auth = self._get_basic_auth_headers(request)
        if basic_auth:
            resp = self._accept(response, environ)
            return resp

        elif request.method not in ('GET', 'HEAD', 'OPTIONS', 'TRACE'):
            # To turn off csrfmiddleware just add csrf.unprotected_path = host_url
            # Check to see if we want to process the post at all
            if (self.unprotected_path is not None
                and request.path_info.startswith(self.unprotected_path)):
                resp = request.get_response(self.app)
                return resp

            if self.is_secure(request):
                # Check the referer. Reject if it's not from the same host.
                referer = request.referer
                if not referer:
                    return self._reject(request, REASON_NO_REFERER)

                good_referer = 'https://{}/'.format(request.host)
                if not referer.startswith(good_referer):
                    return self._reject(request, REASON_BAD_REFERER)

            if not incoming_csrf_cookie:
                # No CSRF cookie. For POST requests, we insist on a CSRF cookie,
                # and in this way we can avoid all CSRF attacks, including login
                # CSRF.
                return self._reject(request, REASON_NO_CSRF_COOKIE)

            # Try to get the csrf token from other places
            request_csrf_token = ''
            if request.method == "POST":
                try:
                    request_csrf_token = request.POST.get(_CSRF_HTML_NAME, '')
                except IOError:
                    # Handle a broken connection before we've completed reading
                    # the POST data. process_view shouldn't raise any
                    # exceptions, so we'll ignore and serve the user a 403
                    # (assuming they're still listening, which they probably
                    # aren't because of the error).
                    pass

            if request_csrf_token == "":
                # Fall back to X-CSRFToken, to make things easier for AJAX,
                # and possible for PUT/DELETE.
                request_csrf_token = request.headers.get(_CSRF_HEADER_NAME, '')

            if not request_csrf_token == correct_csrf_token:
                return self._reject(request, REASON_BAD_TOKEN)

        # If we're a get, we don't do any checking
        resp = self._accept(request, environ)
        return resp


    def __call__(self, environ, start_response):
        request = Request(environ)
        session = environ['beaker.session']
        session.save()

        correct_csrf_token = hmac.new(self.csrf_secret, session.id).hexdigest()

        resp = self._check_request(request, correct_csrf_token, environ)

        # Set csrf cookie anyway, cause all responses need it.
        resp.set_cookie(_CSRF_COOKIE_NAME, correct_csrf_token)

        if resp.content_type.split(';')[0] in _HTML_TYPES:
            # Ensure we don't add the 'id' attribute twice (HTML validity)
            idattributes = itertools.chain(('id={}'.format(_CSRF_HTML_NAME),), 
                                            itertools.repeat(''))
            def add_csrf_field(match):
                """Returns the matched <form> tag plus the added <input> element"""
                return match.group() + '<div style="display:none;">' + \
                '<input type="hidden" ' + idattributes.next() + \
                ' name={} value="'.format(_CSRF_HTML_NAME) + correct_csrf_token + \
                '" /></div>'

            # Modify any POST forms and fix content-length
            resp.body = _POST_FORM_RE.sub(add_csrf_field, resp.body)

        return resp(environ, start_response)


def make_csrf_filter(global_conf, **kw):
    """this is suitable for the paste filter entry point"""
    def filter(app):
        return CsrfMiddleware(app, kw)
    return filter

def make_csrf_filter_app(app, global_conf, **kw):
    """this is suitable for the paste filter-app entry point"""
    return CsrfMiddleware(app, kw)
