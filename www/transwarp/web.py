#!/usr/bin/env python 
# -*- coding: utf-8 -*- 
 
''' 
A simple, lightweight, WSGI-compatible web framework. 
''' 
 
__author__ = 'Michael Liao' 
 
import types, os, re, cgi, sys, time, datetime, functools, mimetypes, threading, logging, urllib, traceback 
 
try: 
    from cStringIO import StringIO 
except ImportError: 
    from StringIO import StringIO 

# thread local object for storing request and response: 

ctx = threading.local() 

# Dict object: 

class Dict(dict): 
   ''' 
    Simple dict but support access as x.y style. 

    >>> d1 = Dict() 
    >>> d1['x'] = 100 
    >>> d1.x 
    100 
    >>> d1.y = 200 
    >>> d1['y'] 
    200 
    >>> d2 = Dict(a=1, b=2, c='3') 
    >>> d2.c 
    '3' 
    >>> d2['empty'] 
    Traceback (most recent call last): 
        ... 
    KeyError: 'empty' 
    >>> d2.empty 
    Traceback (most recent call last): 
        ... 
    AttributeError: 'Dict' object has no attribute 'empty' 
    >>> d3 = Dict(('a', 'b', 'c'), (1, 2, 3)) 
    >>> d3.a 
    1 
    >>> d3.b 
    2 
    >>> d3.c 
    3 
    ''' 
    def __init__(self, names=(), values=(), **kw): 
        super(Dict, self).__init__(**kw) 
        for k, v in zip(names, values): 
            self[k] = v 

    def __getattr__(self, key): 
        try: 
            return self[key] 
        except KeyError: 
            raise AttributeError(r"'Dict' object has no attribute '%s'" % key) 

    def __setattr__(self, key, value): 
        self[key] = value 
 
_TIMEDELTA_ZERO = datetime.timedelta(0) 

# timezone as UTC+8:00, UTC-10:00 

_RE_TZ = re.compile('^([\+\-])([0-9]{1,2})\:([0-9]{1,2})$') 
 
class UTC(datetime.tzinfo): 
    ''' 
    A UTC tzinfo object.  
 
    >>> tz0 = UTC('+00:00') 
    >>> tz0.tzname(None) 
    'UTC+00:00' 
    >>> tz8 = UTC('+8:00') 
    >>> tz8.tzname(None) 
    'UTC+8:00' 
    >>> tz7 = UTC('+7:30') 
    >>> tz7.tzname(None) 
    'UTC+7:30' 
    >>> tz5 = UTC('-05:30') 
    >>> tz5.tzname(None) 
    'UTC-05:30' 
    >>> from datetime import datetime 
    >>> u = datetime.utcnow().replace(tzinfo=tz0) 
    >>> l1 = u.astimezone(tz8) 
    >>> l2 = u.replace(tzinfo=tz8) 
    >>> d1 = u - l1 
    >>> d2 = u - l2 
    >>> d1.seconds 
    0 
    >>> d2.seconds 
    28800 
    ''' 

    def __init__(self, utc): 
         utc = str(utc.strip().upper()) 
         mt = _RE_TZ.match(utc) 
         if mt: 
             minus = mt.group(1)=='-' 
            h = int(mt.group(2)) 
            m = int(mt.group(3)) 
            if minus: 
                h, m = (-h), (-m) 
            self._utcoffset = datetime.timedelta(hours=h, minutes=m) 
            self._tzname = 'UTC%s' % utc 
        else: 
            raise ValueError('bad utc time zone') 

     def utcoffset(self, dt): 
        return self._utcoffset 

    def dst(self, dt): 
        return _TIMEDELTA_ZERO 

    def tzname(self, dt): 
        return self._tzname 

    def __str__(self): 
        return 'UTC tzinfo object (%s)' % self._tzname 

    __repr__ = __str__ 

# all known response statues: 

_RESPONSE_STATUSES = { 
    # Informational 
    100: 'Continue', 
    101: 'Switching Protocols', 
    102: 'Processing', 

    # Successful 
    200: 'OK', 
    201: 'Created', 
    202: 'Accepted', 
    203: 'Non-Authoritative Information', 
    204: 'No Content', 
    205: 'Reset Content', 
    206: 'Partial Content', 
    207: 'Multi Status', 
    226: 'IM Used', 

    # Redirection 
    300: 'Multiple Choices', 
    301: 'Moved Permanently', 
    302: 'Found', 
    303: 'See Other', 
    304: 'Not Modified', 
    305: 'Use Proxy', 
    307: 'Temporary Redirect', 
 
    # Client Error 
    400: 'Bad Request', 
    401: 'Unauthorized', 
    402: 'Payment Required', 
    403: 'Forbidden', 
    404: 'Not Found', 
    405: 'Method Not Allowed', 
    406: 'Not Acceptable', 
    407: 'Proxy Authentication Required', 
    408: 'Request Timeout', 
    409: 'Conflict', 
    410: 'Gone', 
    411: 'Length Required', 
    412: 'Precondition Failed', 
    413: 'Request Entity Too Large', 
    414: 'Request URI Too Long', 
    415: 'Unsupported Media Type', 
    416: 'Requested Range Not Satisfiable', 
    417: 'Expectation Failed', 
    418: "I'm a teapot", 
    422: 'Unprocessable Entity', 
    423: 'Locked', 
    424: 'Failed Dependency', 
    426: 'Upgrade Required', 

    # Server Error 
    500: 'Internal Server Error', 
    501: 'Not Implemented', 
    502: 'Bad Gateway', 
    503: 'Service Unavailable', 
    504: 'Gateway Timeout', 
    505: 'HTTP Version Not Supported', 
    507: 'Insufficient Storage', 
    510: 'Not Extended', 
} 

_RE_RESPONSE_STATUS = re.compile(r'^\d\d\d(\ [\w\ ]+)?$') 
 
_RESPONSE_HEADERS = ( 
    'Accept-Ranges', 
    'Age', 
    'Allow', 
    'Cache-Control', 
    'Connection', 
    'Content-Encoding', 
    'Content-Language', 
    'Content-Length', 
    'Content-Location', 
    'Content-MD5', 
    'Content-Disposition', 
    'Content-Range', 
    'Content-Type', 
    'Date', 
    'ETag', 
    'Expires', 
    'Last-Modified', 
    'Link', 
    'Location', 
    'P3P', 
    'Pragma', 
    'Proxy-Authenticate', 
    'Refresh', 
    'Retry-After', 
    'Server', 
    'Set-Cookie', 
    'Strict-Transport-Security', 
    'Trailer', 
    'Transfer-Encoding', 
    'Vary', 
    'Via', 
    'Warning', 
    'WWW-Authenticate', 
    'X-Frame-Options', 
    'X-XSS-Protection', 
    'X-Content-Type-Options', 
    'X-Forwarded-Proto', 
    'X-Powered-By', 
    'X-UA-Compatible', 
) 
 
_RESPONSE_HEADER_DICT = dict(zip(map(lambda x: x.upper(), _RESPONSE_HEADERS), _RESPONSE_HEADERS)) 

_HEADER_X_POWERED_BY = ('X-Powered-By', 'transwarp/1.0') 

class HttpError(Exception): 
    ''' 
    HttpError that defines http error code. 
 
    >>> e = HttpError(404) 
    >>> e.status 
    '404 Not Found' 
    ''' 
    def __init__(self, code): 
        ''' 
        Init an HttpError with response code. 
        ''' 
        super(HttpError, self).__init__() 
        self.status = '%d %s' % (code, _RESPONSE_STATUSES[code]) 

    def header(self, name, value): 
        if not hasattr(self, '_headers'): 
            self._headers = [_HEADER_X_POWERED_BY] 
        self._headers.append((name, value)) 

    @property 
    def headers(self): 
        if hasattr(self, '_headers'): 
            return self._headers 
        return [] 

    def __str__(self): 
       return self.status 

    __repr__ = __str__ 
 
class RedirectError(HttpError): 
    ''' 
    RedirectError that defines http redirect code. 
 
    >>> e = RedirectError(302, 'http://www.apple.com/') 
    >>> e.status 
    '302 Found' 
    >>> e.location 
    'http://www.apple.com/' 
    ''' 
    def __init__(self, code, location): 
        ''' 
        Init an HttpError with response code. 
        ''' 
        super(RedirectError, self).__init__(code) 
        self.location = location 

    def __str__(self): 
        return '%s, %s' % (self.status, self.location) 

    __repr__ = __str__ 

 def badrequest(): 
    ''' 
    Send a bad request response. 

    >>> raise badrequest() 
    Traceback (most recent call last): 
     ... 
    HttpError: 400 Bad Request 
   ''' 
   return HttpError(400) 

def unauthorized(): 
   ''' 
  Send an unauthorized response. 
 
  >>> raise unauthorized() 
  Traceback (most recent call last): 
     ... 
    HttpError: 401 Unauthorized 
   ''' 
    return HttpError(401) 
 
def forbidden(): 
   ''' 
   Send a forbidden response. 
 
    >>> raise forbidden() 
    Traceback (most recent call last): 
      ... 
    HttpError: 403 Forbidden 
    ''' 
    return HttpError(403) 

def notfound(): 
    ''' 
    Send a not found response. 
  
    >>> raise notfound() 
    Traceback (most recent call last): 
      ... 
    HttpError: 404 Not Found 
    ''' 
    return HttpError(404) 
 
def conflict(): 
    ''' 
    Send a conflict response. 
 
    >>> raise conflict() 
    Traceback (most recent call last): 
     ... 
    HttpError: 409 Conflict 
    ''' 
    return HttpError(409) 

def internalerror(): 
    ''' 
    Send an internal error response. 
 
    >>> raise internalerror() 
    Traceback (most recent call last): 
      ... 
    HttpError: 500 Internal Server Error 
    ''' 
    return HttpError(500) 

def redirect(location): 
    ''' 
    Do permanent redirect. 

    >>> raise redirect('http://www.itranswarp.com/') 
    Traceback (most recent call last): 
      ... 
    RedirectError: 301 Moved Permanently, http://www.itranswarp.com/ 
    ''' 
    return RedirectError(301, location) 

def found(location): 
    ''' 
    Do temporary redirect. 
 
   >>> raise found('http://www.itranswarp.com/') 
    Traceback (most recent call last): 
      ... 
    RedirectError: 302 Found, http://www.itranswarp.com/ 
    ''' 
    return RedirectError(302, location) 

def seeother(location): 
    ''' 
    Do temporary redirect. 
 
    >>> raise seeother('http://www.itranswarp.com/') 
    Traceback (most recent call last): 
      ... 
    RedirectError: 303 See Other, http://www.itranswarp.com/ 
    >>> e = seeother('http://www.itranswarp.com/seeother?r=123') 
    >>> e.location 
    'http://www.itranswarp.com/seeother?r=123' 
    ''' 
    return RedirectError(303, location) 

def _to_str(s): 
    ''' 
    Convert to str. 
 
    >>> _to_str('s123') == 's123' 
    True 
    >>> _to_str(u'\u4e2d\u6587') == '\xe4\xb8\xad\xe6\x96\x87' 
    True 
    >>> _to_str(-123) == '-123' 
    True 
    ''' 
    if isinstance(s, str): 
        return s 
    if isinstance(s, unicode): 
        return s.encode('utf-8') 
    return str(s) 

def _to_unicode(s, encoding='utf-8'): 
    ''' 
    Convert to unicode. 
 
    >>> _to_unicode('\xe4\xb8\xad\xe6\x96\x87') == u'\u4e2d\u6587' 
    True 
    ''' 
    return s.decode('utf-8') 

def _quote(s, encoding='utf-8'): 
    ''' 
    Url quote as str. 
 
   >>> _quote('http://example/test?a=1+') 
    'http%3A//example/test%3Fa%3D1%2B' 
    >>> _quote(u'hello world!') 
   'hello%20world%21' 
    ''' 
   if isinstance(s, unicode): 
       s = s.encode(encoding) 
    return urllib.quote(s) 

def _unquote(s, encoding='utf-8'): 
    ''' 
    Url unquote as unicode. 
 
   >>> _unquote('http%3A//example/test%3Fa%3D1+') 
   u'http://example/test?a=1+' 
    ''' 
   return urllib.unquote(s).decode(encoding) 

def get(path): 
   ''' 
    A @get decorator. 
 
    @get('/:id') 
    def index(id): 
        pass 
 
    >>> @get('/test/:id') 
    ... def test(): 
    ...     return 'ok' 
    ... 
    >>> test.__web_route__ 
    '/test/:id' 
    >>> test.__web_method__ 
    'GET' 
    >>> test() 
    'ok' 
    ''' 
    def _decorator(func): 
        func.__web_route__ = path 
        func.__web_method__ = 'GET' 
        return func 
    return _decorator 
 
def post(path): 
   ''' 
    A @post decorator. 
 
    >>> @post('/post/:id') 
    ... def testpost(): 
    ...     return '200' 
    ... 
    >>> testpost.__web_route__ 
    '/post/:id' 
    >>> testpost.__web_method__ 
    'POST' 
    >>> testpost() 
    '200' 
    ''' 
    def _decorator(func): 
        func.__web_route__ = path 
        func.__web_method__ = 'POST' 
        return func 
     return _decorator 

_re_route = re.compile(r'(\:[a-zA-Z_]\w*)') 
 
def _build_regex(path): 
    r''' 
    Convert route path to regex. 
 
    >>> _build_regex('/path/to/:file') 
    '^\\/path\\/to\\/(?P<file>[^\\/]+)$' 
     >>> _build_regex('/:user/:comments/list') 
    '^\\/(?P<user>[^\\/]+)\\/(?P<comments>[^\\/]+)\\/list$' 
    >>> _build_regex(':id-:pid/:w') 
    '^(?P<id>[^\\/]+)\\-(?P<pid>[^\\/]+)\\/(?P<w>[^\\/]+)$' 
    ''' 
    re_list = ['^'] 
    var_list = [] 
    is_var = False 
    for v in _re_route.split(path): 
        if is_var: 
             var_name = v[1:] 
             var_list.append(var_name) 
             re_list.append(r'(?P<%s>[^\/]+)' % var_name) 
         else: 
            s = '' 
            for ch in v: 
                if ch>='0' and ch<='9': 
                    s = s + ch 
                elif ch>='A' and ch<='Z': 
                   s = s + ch 
                elif ch>='a' and ch<='z': 
                    s = s + ch 
                else: 
                    s = s + '\\' + ch 
            re_list.append(s) 
        is_var = not is_var 
    re_list.append('$') 
    return ''.join(re_list) 

class Route(object): 
    ''' 
    A Route object is a callable object. 
    ''' 

    def __init__(self, func): 
        self.path = func.__web_route__ 
        self.method = func.__web_method__ 
        self.is_static = _re_route.search(self.path) is None 
        if not self.is_static: 
            self.route = re.compile(_build_regex(self.path)) 
        self.func = func 

    def match(self, url): 
        m = self.route.match(url) 
        if m: 
            return m.groups() 
        return None 

    def __call__(self, *args): 
        return self.func(*args) 

    def __str__(self): 
       if self.is_static: 
            return 'Route(static,%s,path=%s)' % (self.method, self.path) 
        return 'Route(dynamic,%s,path=%s)' % (self.method, self.path) 

    __repr__ = __str__ 

def _static_file_generator(fpath): 
    BLOCK_SIZE = 8192 
    with open(fpath, 'rb') as f: 
        block = f.read(BLOCK_SIZE) 
        while block: 
            yield block 
            block = f.read(BLOCK_SIZE) 

class StaticFileRoute(object): 

    def __init__(self): 
        self.method = 'GET' 
        self.is_static = False 
        self.route = re.compile('^/static/(.+)$') 

    def match(self, url): 
       if url.startswith('/static/'): 
            return (url[1:], ) 
        return None 

    def __call__(self, *args): 
        fpath = os.path.join(ctx.application.document_root, args[0]) 
        if not os.path.isfile(fpath): 
            raise notfound() 
        fext = os.path.splitext(fpath)[1] 
        ctx.response.content_type = mimetypes.types_map.get(fext.lower(), 'application/octet-stream') 
        return _static_file_generator(fpath) 

def favicon_handler(): 
    return static_file_handler('/favicon.ico') 

class MultipartFile(object): 
    ''' 
    Multipart file storage get from request input. 
 
    f = ctx.request['file'] 
    f.filename # 'test.png' 
    f.file # file-like object 
    ''' 
    def __init__(self, storage): 
        self.filename = _to_unicode(storage.filename) 
        self.file = storage.file 


class Request(object): 
    ''' 
    Request object for obtaining all http request information. 
    ''' 
    def __init__(self, environ): 
         self._environ = environ 

    def _parse_input(self): 
        def _convert(item): 
            if isinstance(item, list): 
                return [_to_unicode(i.value) for i in item] 
           if item.filename: 
                return MultipartFile(item) 
           return _to_unicode(item.value) 
        fs = cgi.FieldStorage(fp=self._environ['wsgi.input'], environ=self._environ, keep_blank_values=True) 
        inputs = dict() 
        for key in fs: 
            inputs[key] = _convert(fs[key]) 
        return inputs 

    def _get_raw_input(self): 
        ''' 
        Get raw input as dict containing values as unicode, list or MultipartFile. 
        ''' 
        if not hasattr(self, '_raw_input'): 
            self._raw_input = self._parse_input() 
        return self._raw_input 

    def __getitem__(self, key): 
        ''' 
        Get input parameter value. If the specified key has multiple value, the first one is returned. 
        If the specified key is not exist, then raise KeyError. 
 
        >>> from StringIO import StringIO 
        >>> r = Request({'REQUEST_METHOD':'POST', 'wsgi.input':StringIO('a=1&b=M%20M&c=ABC&c=XYZ&e=')}) 
        >>> r['a'] 
        u'1' 
        >>> r['c'] 
        u'ABC' 
        >>> r['empty'] 
        Traceback (most recent call last): 
            ... 
        KeyError: 'empty' 
        >>> b = '----WebKitFormBoundaryQQ3J8kPsjFpTmqNz' 
        >>> pl = ['--%s' % b, 'Content-Disposition: form-data; name=\\"name\\"\\n', 'Scofield', '--%s' % b, 'Content-Disposition: form-data; name=\\"name\\"\\n', 'Lincoln', '--%s' % b, 'Content-Disposition: form-data; name=\\"file\\"; filename=\\"test.txt\\"', 'Content-Type: text/plain\\n', 'just a test', '--%s' % b, 'Content-Disposition: form-data; name=\\"id\\"\\n', '4008009001', '--%s--' % b, ''] 
        >>> payload = '\\n'.join(pl) 
        >>> r = Request({'REQUEST_METHOD':'POST', 'CONTENT_LENGTH':str(len(payload)), 'CONTENT_TYPE':'multipart/form-data; boundary=%s' % b, 'wsgi.input':StringIO(payload)}) 
        >>> r.get('name') 
        u'Scofield' 
        >>> r.gets('name') 
        [u'Scofield', u'Lincoln'] 
        >>> f = r.get('file') 
        >>> f.filename 
        u'test.txt' 
        >>> f.file.read() 
       'just a test' 
        ''' 
        r = self._get_raw_input()[key] 
        if isinstance(r, list): 
            return r[0] 
        return r 

    def get(self, key, default=None): 
        ''' 
        The same as request[key], but return default value if key is not found. 
 
        >>> from StringIO import StringIO 
        >>> r = Request({'REQUEST_METHOD':'POST', 'wsgi.input':StringIO('a=1&b=M%20M&c=ABC&c=XYZ&e=')}) 
        >>> r.get('a') 
        u'1' 
        >>> r.get('empty') 
        >>> r.get('empty', 'DEFAULT') 
        'DEFAULT' 
        ''' 
        r = self._get_raw_input().get(key, default) 
        if isinstance(r, list): 
            return r[0] 
        return r 

    def gets(self, key): 
        ''' 
        Get multiple values for specified key. 
 
        >>> from StringIO import StringIO 
        >>> r = Request({'REQUEST_METHOD':'POST', 'wsgi.input':StringIO('a=1&b=M%20M&c=ABC&c=XYZ&e=')}) 
        >>> r.gets('a') 
        [u'1'] 
        >>> r.gets('c') 
        [u'ABC', u'XYZ'] 
        >>> r.gets('empty') 
        Traceback (most recent call last): 
            ... 
        KeyError: 'empty' 
        ''' 
        r = self._get_raw_input()[key] 
        if isinstance(r, list): 
            return r[:] 
        return [r] 
 
    def input(self, **kw): 
        ''' 
        Get input as dict from request, fill dict using provided default value if key not exist. 
 
        i = ctx.request.input(role='guest') 
        i.role ==> 'guest' 
 
        >>> from StringIO import StringIO 
        >>> r = Request({'REQUEST_METHOD':'POST', 'wsgi.input':StringIO('a=1&b=M%20M&c=ABC&c=XYZ&e=')}) 
        >>> i = r.input(x=2008) 
        >>> i.a 
        u'1' 
        >>> i.b 
        u'M M' 
        >>> i.c 
        u'ABC' 
        >>> i.x 
        2008 
        >>> i.get('d', u'100') 
        u'100' 
        >>> i.x 
        2008 
        ''' 
        copy = Dict(**kw) 
        raw = self._get_raw_input() 
        for k, v in raw.iteritems(): 
            copy[k] = v[0] if isinstance(v, list) else v 
        return copy 

    def get_body(self): 
       ''' 
        Get raw data from HTTP POST and return as str. 

        >>> from StringIO import StringIO 
        >>> r = Request({'REQUEST_METHOD':'POST', 'wsgi.input':StringIO('<xml><raw/>')}) 
        >>> r.get_body() 
        '<xml><raw/>' 
        ''' 
        fp = self._environ['wsgi.input'] 
        return fp.read() 

    @property 
    def remote_addr(self): 
        ''' 
        Get remote addr. Return '0.0.0.0' if cannot get remote_addr. 
 
        >>> r = Request({'REMOTE_ADDR': '192.168.0.100'}) 
        >>> r.remote_addr 
        '192.168.0.100' 
        ''' 
        return self._environ.get('REMOTE_ADDR', '0.0.0.0') 
 
    @property 
    def document_root(self): 
        ''' 
        Get raw document_root as str. Return '' if no document_root. 

        >>> r = Request({'DOCUMENT_ROOT': '/srv/path/to/doc'}) 
        >>> r.document_root 
        '/srv/path/to/doc' 
        ''' 
        return self._environ.get('DOCUMENT_ROOT', '') 

    @property 
    def query_string(self): 
        ''' 
        Get raw query string as str. Return '' if no query string. 

        >>> r = Request({'QUERY_STRING': 'a=1&c=2'}) 
       >>> r.query_string 
        'a=1&c=2' 
        >>> r = Request({}) 
        >>> r.query_string 
        '' 
        ''' 
        return self._environ.get('QUERY_STRING', '') 

     @property 
    def environ(self): 
        ''' 
      Get raw environ as dict, both key, value are str. 
 
        >>> r = Request({'REQUEST_METHOD': 'GET', 'wsgi.url_scheme':'http'}) 
        >>> r.environ.get('REQUEST_METHOD') 
        'GET' 
        >>> r.environ.get('wsgi.url_scheme') 
        'http' 
        >>> r.environ.get('SERVER_NAME') 
        >>> r.environ.get('SERVER_NAME', 'unamed') 
       'unamed' 
        ''' 
        return self._environ 
 
    @property 
    def request_method(self): 
        ''' 
        Get request method. The valid returned values are 'GET', 'POST', 'HEAD'. 
 
        >>> r = Request({'REQUEST_METHOD': 'GET'}) 
        >>> r.request_method 
        'GET' 
        >>> r = Request({'REQUEST_METHOD': 'POST'}) 
        >>> r.request_method 
        'POST' 
        ''' 
        return self._environ['REQUEST_METHOD'] 


  @property 
807     def path_info(self): 
808         ''' 
809         Get request path as str. 
810  
811         >>> r = Request({'PATH_INFO': '/test/a%20b.html'}) 
812         >>> r.path_info 
813         '/test/a b.html' 
814         ''' 
815         return urllib.unquote(self._environ.get('PATH_INFO', '')) 
816 
 
817     @property 
818     def host(self): 
819         ''' 
820         Get request host as str. Default to '' if cannot get host.. 
821  
822         >>> r = Request({'HTTP_HOST': 'localhost:8080'}) 
823         >>> r.host 
824         'localhost:8080' 
825         ''' 
826         return self._environ.get('HTTP_HOST', '') 
827 
 
828     def _get_headers(self): 
829         if not hasattr(self, '_headers'): 
830             hdrs = {} 
831             for k, v in self._environ.iteritems(): 
832                 if k.startswith('HTTP_'): 
833                     # convert 'HTTP_ACCEPT_ENCODING' to 'ACCEPT-ENCODING' 
834                     hdrs[k[5:].replace('_', '-').upper()] = v.decode('utf-8') 
835             self._headers = hdrs 
836         return self._headers 
837 
 
838     @property 
839     def headers(self): 
840         ''' 
841         Get all HTTP headers with key as str and value as unicode. The header names are 'XXX-XXX' uppercase. 
842  
843         >>> r = Request({'HTTP_USER_AGENT': 'Mozilla/5.0', 'HTTP_ACCEPT': 'text/html'}) 
844         >>> H = r.headers 
845         >>> H['ACCEPT'] 
846         u'text/html' 
847         >>> H['USER-AGENT'] 
848         u'Mozilla/5.0' 
849         >>> L = H.items() 
850         >>> L.sort() 
851         >>> L 
852         [('ACCEPT', u'text/html'), ('USER-AGENT', u'Mozilla/5.0')] 
853         ''' 
854         return dict(**self._get_headers()) 
855 
 
856     def header(self, header, default=None): 
857         ''' 
858         Get header from request as unicode, return None if not exist, or default if specified.  
859         The header name is case-insensitive such as 'USER-AGENT' or u'content-Type'. 
860  
861         >>> r = Request({'HTTP_USER_AGENT': 'Mozilla/5.0', 'HTTP_ACCEPT': 'text/html'}) 
862         >>> r.header('User-Agent') 
863         u'Mozilla/5.0' 
864         >>> r.header('USER-AGENT') 
865         u'Mozilla/5.0' 
866         >>> r.header('Accept') 
867         u'text/html' 
868         >>> r.header('Test') 
869         >>> r.header('Test', u'DEFAULT') 
870         u'DEFAULT' 
871         ''' 
872         return self._get_headers().get(header.upper(), default) 
873 
 
874     def _get_cookies(self): 
875         if not hasattr(self, '_cookies'): 
876             cookies = {} 
877             cookie_str = self._environ.get('HTTP_COOKIE') 
878             if cookie_str: 
879                 for c in cookie_str.split(';'): 
880                     pos = c.find('=') 
881                     if pos>0: 
882                         cookies[c[:pos].strip()] = _unquote(c[pos+1:]) 
883             self._cookies = cookies 
884         return self._cookies 
885 
 
886     @property 
887     def cookies(self): 
888         ''' 
889         Return all cookies as dict. The cookie name is str and values is unicode. 
890  
891         >>> r = Request({'HTTP_COOKIE':'A=123; url=http%3A%2F%2Fwww.example.com%2F'}) 
892         >>> r.cookies['A'] 
893         u'123' 
894         >>> r.cookies['url'] 
895         u'http://www.example.com/' 
896         ''' 
897         return Dict(**self._get_cookies()) 
898 
 
899     def cookie(self, name, default=None): 
900         ''' 
901         Return specified cookie value as unicode. Default to None if cookie not exists. 
902  
903         >>> r = Request({'HTTP_COOKIE':'A=123; url=http%3A%2F%2Fwww.example.com%2F'}) 
904         >>> r.cookie('A') 
905         u'123' 
906         >>> r.cookie('url') 
907         u'http://www.example.com/' 
908         >>> r.cookie('test') 
909         >>> r.cookie('test', u'DEFAULT') 
910         u'DEFAULT' 
911         ''' 
912         return self._get_cookies().get(name, default) 
913 
 
914 UTC_0 = UTC('+00:00') 
915 
 
916 class Response(object): 
917 
 
918     def __init__(self): 
919         self._status = '200 OK' 
920         self._headers = {'CONTENT-TYPE': 'text/html; charset=utf-8'} 
921 
 
922     @property 
923     def headers(self): 
924         ''' 
925         Return response headers as [(key1, value1), (key2, value2)...] including cookies. 
926  
927         >>> r = Response() 
928         >>> r.headers 
929         [('Content-Type', 'text/html; charset=utf-8'), ('X-Powered-By', 'transwarp/1.0')] 
930         >>> r.set_cookie('s1', 'ok', 3600) 
931         >>> r.headers 
932         [('Content-Type', 'text/html; charset=utf-8'), ('Set-Cookie', 's1=ok; Max-Age=3600; Path=/; HttpOnly'), ('X-Powered-By', 'transwarp/1.0')] 
933         ''' 
934         L = [(_RESPONSE_HEADER_DICT.get(k, k), v) for k, v in self._headers.iteritems()] 
935         if hasattr(self, '_cookies'): 
936             for v in self._cookies.itervalues(): 
937                 L.append(('Set-Cookie', v)) 
938         L.append(_HEADER_X_POWERED_BY) 
939         return L 
940 
 
941     def header(self, name): 
942         ''' 
943         Get header by name, case-insensitive. 
944  
945         >>> r = Response() 
946         >>> r.header('content-type') 
947         'text/html; charset=utf-8' 
948         >>> r.header('CONTENT-type') 
949         'text/html; charset=utf-8' 
950         >>> r.header('X-Powered-By') 
951         ''' 
952         key = name.upper() 
953         if not key in _RESPONSE_HEADER_DICT: 
954             key = name 
955         return self._headers.get(key) 
956 
 
957     def unset_header(self, name): 
958         ''' 
959         Unset header by name and value. 
960  
961         >>> r = Response() 
962         >>> r.header('content-type') 
963         'text/html; charset=utf-8' 
964         >>> r.unset_header('CONTENT-type') 
965         >>> r.header('content-type') 
966         ''' 
967         key = name.upper() 
968         if not key in _RESPONSE_HEADER_DICT: 
969             key = name 
970         if key in self._headers: 
971             del self._headers[key] 
972 
 
973     def set_header(self, name, value): 
974         ''' 
975         Set header by name and value. 
976  
977         >>> r = Response() 
978         >>> r.header('content-type') 
979         'text/html; charset=utf-8' 
980         >>> r.set_header('CONTENT-type', 'image/png') 
981         >>> r.header('content-TYPE') 
982         'image/png' 
983         ''' 
984         key = name.upper() 
985         if not key in _RESPONSE_HEADER_DICT: 
986             key = name 
987         self._headers[key] = _to_str(value) 
988 
 
989     @property 
990     def content_type(self): 
991         ''' 
992         Get content type from response. This is a shortcut for header('Content-Type'). 
993  
994         >>> r = Response() 
995         >>> r.content_type 
996         'text/html; charset=utf-8' 
997         >>> r.content_type = 'application/json' 
998         >>> r.content_type 
999         'application/json' 
1000         ''' 
1001         return self.header('CONTENT-TYPE') 
1002 
 
1003     @content_type.setter 
1004     def content_type(self, value): 
1005         ''' 
1006         Set content type for response. This is a shortcut for set_header('Content-Type', value). 
1007         ''' 
1008         if value: 
1009             self.set_header('CONTENT-TYPE', value) 
1010         else: 
1011             self.unset_header('CONTENT-TYPE') 
1012 
 
1013     @property 
1014     def content_length(self): 
1015         ''' 
1016         Get content length. Return None if not set. 
1017  
1018         >>> r = Response() 
1019         >>> r.content_length 
1020         >>> r.content_length = 100 
1021         >>> r.content_length 
1022         '100' 
1023         ''' 
1024         return self.header('CONTENT-LENGTH') 
1025 
 
1026     @content_length.setter 
1027     def content_length(self, value): 
1028         ''' 
1029         Set content length, the value can be int or str. 
1030  
1031         >>> r = Response() 
1032         >>> r.content_length = '1024' 
1033         >>> r.content_length 
1034         '1024' 
1035         >>> r.content_length = 1024 * 8 
1036         >>> r.content_length 
1037         '8192' 
1038         ''' 
1039         self.set_header('CONTENT-LENGTH', str(value)) 
1040 
 
1041     def delete_cookie(self, name): 
1042         ''' 
1043         Delete a cookie immediately. 
1044  
1045         Args: 
1046           name: the cookie name. 
1047         ''' 
1048         self.set_cookie(name, '__deleted__', expires=0) 
1049 
 
1050     def set_cookie(self, name, value, max_age=None, expires=None, path='/', domain=None, secure=False, http_only=True): 
1051         ''' 
1052         Set a cookie. 
1053  
1054         Args: 
1055           name: the cookie name. 
1056           value: the cookie value. 
1057           max_age: optional, seconds of cookie's max age. 
1058           expires: optional, unix timestamp, datetime or date object that indicate an absolute time of the  
1059                    expiration time of cookie. Note that if expires specified, the max_age will be ignored. 
1060           path: the cookie path, default to '/'. 
1061           domain: the cookie domain, default to None. 
1062           secure: if the cookie secure, default to False. 
1063           http_only: if the cookie is for http only, default to True for better safty  
1064                      (client-side script cannot access cookies with HttpOnly flag). 
1065  
1066         >>> r = Response() 
1067         >>> r.set_cookie('company', 'Abc, Inc.', max_age=3600) 
1068         >>> r._cookies 
1069         {'company': 'company=Abc%2C%20Inc.; Max-Age=3600; Path=/; HttpOnly'} 
1070         >>> r.set_cookie('company', r'Example="Limited"', expires=1342274794.123, path='/sub/') 
1071         >>> r._cookies 
1072         {'company': 'company=Example%3D%22Limited%22; Expires=Sat, 14-Jul-2012 14:06:34 GMT; Path=/sub/; HttpOnly'} 
1073         >>> dt = datetime.datetime(2012, 7, 14, 22, 6, 34, tzinfo=UTC('+8:00')) 
1074         >>> r.set_cookie('company', 'Expires', expires=dt) 
1075         >>> r._cookies 
1076         {'company': 'company=Expires; Expires=Sat, 14-Jul-2012 14:06:34 GMT; Path=/; HttpOnly'} 
1077         ''' 
1078         if not hasattr(self, '_cookies'): 
1079             self._cookies = {} 
1080         L = ['%s=%s' % (_quote(name), _quote(value))] 
1081         if expires is not None: 
1082             if isinstance(expires, (float, int, long)): 
1083                 L.append('Expires=%s' % datetime.datetime.fromtimestamp(expires, UTC_0).strftime('%a, %d-%b-%Y %H:%M:%S GMT')) 
1084             if isinstance(expires, (datetime.date, datetime.datetime)): 
1085                 L.append('Expires=%s' % expires.astimezone(UTC_0).strftime('%a, %d-%b-%Y %H:%M:%S GMT')) 
1086         elif isinstance(max_age, (int, long)): 
1087             L.append('Max-Age=%d' % max_age) 
1088         L.append('Path=%s' % path) 
1089         if domain: 
1090             L.append('Domain=%s' % domain) 
1091         if secure: 
1092             L.append('Secure') 
1093         if http_only: 
1094             L.append('HttpOnly') 
1095         self._cookies[name] = '; '.join(L) 
1096 
 
1097     def unset_cookie(self, name): 
1098         ''' 
1099         Unset a cookie. 
1100  
1101         >>> r = Response() 
1102         >>> r.set_cookie('company', 'Abc, Inc.', max_age=3600) 
1103         >>> r._cookies 
1104         {'company': 'company=Abc%2C%20Inc.; Max-Age=3600; Path=/; HttpOnly'} 
1105         >>> r.unset_cookie('company') 
1106         >>> r._cookies 
1107         {} 
1108         ''' 
1109         if hasattr(self, '_cookies'): 
1110             if name in self._cookies: 
1111                 del self._cookies[name] 
1112 
 
1113     @property 
1114     def status_code(self): 
1115         ''' 
1116         Get response status code as int. 
1117  
1118         >>> r = Response() 
1119         >>> r.status_code 
1120         200 
1121         >>> r.status = 404 
1122         >>> r.status_code 
1123         404 
1124         >>> r.status = '500 Internal Error' 
1125         >>> r.status_code 
1126         500 
1127         ''' 
1128         return int(self._status[:3]) 
1129 
 
1130     @property 
1131     def status(self): 
1132         ''' 
1133         Get response status. Default to '200 OK'. 
1134  
1135         >>> r = Response() 
1136         >>> r.status 
1137         '200 OK' 
1138         >>> r.status = 404 
1139         >>> r.status 
1140         '404 Not Found' 
1141         >>> r.status = '500 Oh My God' 
1142         >>> r.status 
1143         '500 Oh My God' 
1144         ''' 
1145         return self._status 
1146 
 
1147     @status.setter 
1148     def status(self, value): 
1149         ''' 
1150         Set response status as int or str. 
1151  
1152         >>> r = Response() 
1153         >>> r.status = 404 
1154         >>> r.status 
1155         '404 Not Found' 
1156         >>> r.status = '500 ERR' 
1157         >>> r.status 
1158         '500 ERR' 
1159         >>> r.status = u'403 Denied' 
1160         >>> r.status 
1161         '403 Denied' 
1162         >>> r.status = 99 
1163         Traceback (most recent call last): 
1164           ... 
1165         ValueError: Bad response code: 99 
1166         >>> r.status = 'ok' 
1167         Traceback (most recent call last): 
1168           ... 
1169         ValueError: Bad response code: ok 
1170         >>> r.status = [1, 2, 3] 
1171         Traceback (most recent call last): 
1172           ... 
1173         TypeError: Bad type of response code. 
1174         ''' 
1175         if isinstance(value, (int, long)): 
1176             if value>=100 and value<=999: 
1177                 st = _RESPONSE_STATUSES.get(value, '') 
1178                 if st: 
1179                     self._status = '%d %s' % (value, st) 
1180                 else: 
1181                     self._status = str(value) 
1182             else: 
1183                 raise ValueError('Bad response code: %d' % value) 
1184         elif isinstance(value, basestring): 
1185             if isinstance(value, unicode): 
1186                 value = value.encode('utf-8') 
1187             if _RE_RESPONSE_STATUS.match(value): 
1188                 self._status = value 
1189             else: 
1190                 raise ValueError('Bad response code: %s' % value) 
1191         else: 
1192             raise TypeError('Bad type of response code.') 
1193 
 
1194 class Template(object): 
1195 
 
1196     def __init__(self, template_name, **kw): 
1197         ''' 
1198         Init a template object with template name, model as dict, and additional kw that will append to model. 
1199  
1200         >>> t = Template('hello.html', title='Hello', copyright='@2012') 
1201         >>> t.model['title'] 
1202         'Hello' 
1203         >>> t.model['copyright'] 
1204         '@2012' 
1205         >>> t = Template('test.html', abc=u'ABC', xyz=u'XYZ') 
1206         >>> t.model['abc'] 
1207         u'ABC' 
1208         ''' 
1209         self.template_name = template_name 
1210         self.model = dict(**kw) 
1211 
 
1212 class TemplateEngine(object): 
1213     ''' 
1214     Base template engine. 
1215     ''' 
1216     def __call__(self, path, model): 
1217         return '<!-- override this method to render template -->' 
1218 
 
1219 class Jinja2TemplateEngine(TemplateEngine): 
1220 
 
1221     ''' 
1222     Render using jinja2 template engine. 
1223  
1224     >>> templ_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'test') 
1225     >>> engine = Jinja2TemplateEngine(templ_path) 
1226     >>> engine.add_filter('datetime', lambda dt: dt.strftime('%Y-%m-%d %H:%M:%S')) 
1227     >>> engine('jinja2-test.html', dict(name='Michael', posted_at=datetime.datetime(2014, 6, 1, 10, 11, 12))) 
1228     '<p>Hello, Michael.</p><span>2014-06-01 10:11:12</span>' 
1229     ''' 
1230 
 
1231     def __init__(self, templ_dir, **kw): 
1232         from jinja2 import Environment, FileSystemLoader 
1233         if not 'autoescape' in kw: 
1234             kw['autoescape'] = True 
1235         self._env = Environment(loader=FileSystemLoader(templ_dir), **kw) 
1236 
 
1237     def add_filter(self, name, fn_filter): 
1238         self._env.filters[name] = fn_filter 
1239 
 
1240     def __call__(self, path, model): 
1241         return self._env.get_template(path).render(**model).encode('utf-8') 
1242 
 
1243 def _default_error_handler(e, start_response, is_debug): 
1244     if isinstance(e, HttpError): 
1245         logging.info('HttpError: %s' % e.status) 
1246         headers = e.headers[:] 
1247         headers.append(('Content-Type', 'text/html')) 
1248         start_response(e.status, headers) 
1249         return ('<html><body><h1>%s</h1></body></html>' % e.status) 
1250     logging.exception('Exception:') 
1251     start_response('500 Internal Server Error', [('Content-Type', 'text/html'), _HEADER_X_POWERED_BY]) 
1252     if is_debug: 
1253         return _debug() 
1254     return ('<html><body><h1>500 Internal Server Error</h1><h3>%s</h3></body></html>' % str(e)) 
1255 
 
1256 def view(path): 
1257     ''' 
1258     A view decorator that render a view by dict. 
1259  
1260     >>> @view('test/view.html') 
1261     ... def hello(): 
1262     ...     return dict(name='Bob') 
1263     >>> t = hello() 
1264     >>> isinstance(t, Template) 
1265     True 
1266     >>> t.template_name 
1267     'test/view.html' 
1268     >>> @view('test/view.html') 
1269     ... def hello2(): 
1270     ...     return ['a list'] 
1271     >>> t = hello2() 
1272     Traceback (most recent call last): 
1273       ... 
1274     ValueError: Expect return a dict when using @view() decorator. 
1275     ''' 
1276     def _decorator(func): 
1277         @functools.wraps(func) 
1278         def _wrapper(*args, **kw): 
1279             r = func(*args, **kw) 
1280             if isinstance(r, dict): 
1281                 logging.info('return Template') 
1282                 return Template(path, **r) 
1283             raise ValueError('Expect return a dict when using @view() decorator.') 
1284         return _wrapper 
1285     return _decorator 
1286 
 
1287 _RE_INTERCEPTROR_STARTS_WITH = re.compile(r'^([^\*\?]+)\*?$') 
1288 _RE_INTERCEPTROR_ENDS_WITH = re.compile(r'^\*([^\*\?]+)$') 
1289 
 
1290 def _build_pattern_fn(pattern): 
1291     m = _RE_INTERCEPTROR_STARTS_WITH.match(pattern) 
1292     if m: 
1293         return lambda p: p.startswith(m.group(1)) 
1294     m = _RE_INTERCEPTROR_ENDS_WITH.match(pattern) 
1295     if m: 
1296         return lambda p: p.endswith(m.group(1)) 
1297     raise ValueError('Invalid pattern definition in interceptor.') 
1298 
 
1299 def interceptor(pattern='/'): 
1300     ''' 
1301     An @interceptor decorator. 
1302  
1303     @interceptor('/admin/') 
1304     def check_admin(req, resp): 
1305         pass 
1306     ''' 
1307     def _decorator(func): 
1308         func.__interceptor__ = _build_pattern_fn(pattern) 
1309         return func 
1310     return _decorator 
1311 
 
1312 def _build_interceptor_fn(func, next): 
1313     def _wrapper(): 
1314         if func.__interceptor__(ctx.request.path_info): 
1315             return func(next) 
1316         else: 
1317             return next() 
1318     return _wrapper 
1319 
 
1320 def _build_interceptor_chain(last_fn, *interceptors): 
1321     ''' 
1322     Build interceptor chain. 
1323  
1324     >>> def target(): 
1325     ...     print 'target' 
1326     ...     return 123 
1327     >>> @interceptor('/') 
1328     ... def f1(next): 
1329     ...     print 'before f1()' 
1330     ...     return next() 
1331     >>> @interceptor('/test/') 
1332     ... def f2(next): 
1333     ...     print 'before f2()' 
1334     ...     try: 
1335     ...         return next() 
1336     ...     finally: 
1337     ...         print 'after f2()' 
1338     >>> @interceptor('/') 
1339     ... def f3(next): 
1340     ...     print 'before f3()' 
1341     ...     try: 
1342     ...         return next() 
1343     ...     finally: 
1344     ...         print 'after f3()' 
1345     >>> chain = _build_interceptor_chain(target, f1, f2, f3) 
1346     >>> ctx.request = Dict(path_info='/test/abc') 
1347     >>> chain() 
1348     before f1() 
1349     before f2() 
1350     before f3() 
1351     target 
1352     after f3() 
1353     after f2() 
1354     123 
1355     >>> ctx.request = Dict(path_info='/api/') 
1356     >>> chain() 
1357     before f1() 
1358     before f3() 
1359     target 
1360     after f3() 
1361     123 
1362     ''' 
1363     L = list(interceptors) 
1364     L.reverse() 
1365     fn = last_fn 
1366     for f in L: 
1367         fn = _build_interceptor_fn(f, fn) 
1368     return fn 
1369 
 
1370 def _load_module(module_name): 
1371     ''' 
1372     Load module from name as str. 
1373  
1374     >>> m = _load_module('xml') 
1375     >>> m.__name__ 
1376     'xml' 
1377     >>> m = _load_module('xml.sax') 
1378     >>> m.__name__ 
1379     'xml.sax' 
1380     >>> m = _load_module('xml.sax.handler') 
1381     >>> m.__name__ 
1382     'xml.sax.handler' 
1383     ''' 
1384     last_dot = module_name.rfind('.') 
1385     if last_dot==(-1): 
1386         return __import__(module_name, globals(), locals()) 
1387     from_module = module_name[:last_dot] 
1388     import_module = module_name[last_dot+1:] 
1389     m = __import__(from_module, globals(), locals(), [import_module]) 
1390     return getattr(m, import_module) 
1391 
 
1392 class WSGIApplication(object): 
1393 
 
1394     def __init__(self, document_root=None, **kw): 
1395         ''' 
1396         Init a WSGIApplication. 
1397  
1398         Args: 
1399           document_root: document root path. 
1400         ''' 
1401         self._running = False 
1402         self._document_root = document_root 
1403 
 
1404         self._interceptors = [] 
1405         self._template_engine = None 
1406 
 
1407         self._get_static = {} 
1408         self._post_static = {} 
1409 
 
1410         self._get_dynamic = [] 
1411         self._post_dynamic = [] 
1412 
 
1413     def _check_not_running(self): 
1414         if self._running: 
1415             raise RuntimeError('Cannot modify WSGIApplication when running.') 
1416 
 
1417     @property 
1418     def template_engine(self): 
1419         return self._template_engine 
1420 
 
1421     @template_engine.setter 
1422     def template_engine(self, engine): 
1423         self._check_not_running() 
1424         self._template_engine = engine 
1425 
 
1426     def add_module(self, mod): 
1427         self._check_not_running() 
1428         m = mod if type(mod)==types.ModuleType else _load_module(mod) 
1429         logging.info('Add module: %s' % m.__name__) 
1430         for name in dir(m): 
1431             fn = getattr(m, name) 
1432             if callable(fn) and hasattr(fn, '__web_route__') and hasattr(fn, '__web_method__'): 
1433                 self.add_url(fn) 
1434 
 
1435     def add_url(self, func): 
1436         self._check_not_running() 
1437         route = Route(func) 
1438         if route.is_static: 
1439             if route.method=='GET': 
1440                 self._get_static[route.path] = route 
1441             if route.method=='POST': 
1442                 self._post_static[route.path] = route 
1443         else: 
1444             if route.method=='GET': 
1445                 self._get_dynamic.append(route) 
1446             if route.method=='POST': 
1447                 self._post_dynamic.append(route) 
1448         logging.info('Add route: %s' % str(route)) 
1449 
 
1450     def add_interceptor(self, func): 
1451         self._check_not_running() 
1452         self._interceptors.append(func) 
1453         logging.info('Add interceptor: %s' % str(func)) 
1454 
 
1455     def run(self, port=9000, host='127.0.0.1'): 
1456         from wsgiref.simple_server import make_server 
1457         logging.info('application (%s) will start at %s:%s...' % (self._document_root, host, port)) 
1458         server = make_server(host, port, self.get_wsgi_application(debug=True)) 
1459         server.serve_forever() 
1460 
 
1461     def get_wsgi_application(self, debug=False): 
1462         self._check_not_running() 
1463         if debug: 
1464             self._get_dynamic.append(StaticFileRoute()) 
1465         self._running = True 
1466 
 
1467         _application = Dict(document_root=self._document_root) 
1468 
 
1469         def fn_route(): 
1470             request_method = ctx.request.request_method 
1471             path_info = ctx.request.path_info 
1472             if request_method=='GET': 
1473                 fn = self._get_static.get(path_info, None) 
1474                 if fn: 
1475                     return fn() 
1476                 for fn in self._get_dynamic: 
1477                     args = fn.match(path_info) 
1478                     if args: 
1479                         return fn(*args) 
1480                 raise notfound() 
1481             if request_method=='POST': 
1482                 fn = self._post_static.get(path_info, None) 
1483                 if fn: 
1484                     return fn() 
1485                 for fn in self._post_dynamic: 
1486                     args = fn.match(path_info) 
1487                     if args: 
1488                         return fn(*args) 
1489                 raise notfound() 
1490             raise badrequest() 
1491 
 
1492         fn_exec = _build_interceptor_chain(fn_route, *self._interceptors) 
1493 
 
1494         def wsgi(env, start_response): 
1495             ctx.application = _application 
1496             ctx.request = Request(env) 
1497             response = ctx.response = Response() 
1498             try: 
1499                 r = fn_exec() 
1500                 if isinstance(r, Template): 
1501                     r = self._template_engine(r.template_name, r.model) 
1502                 if isinstance(r, unicode): 
1503                     r = r.encode('utf-8') 
1504                 if r is None: 
1505                     r = [] 
1506                 start_response(response.status, response.headers) 
1507                 return r 
1508             except RedirectError, e: 
1509                 response.set_header('Location', e.location) 
1510                 start_response(e.status, response.headers) 
1511                 return [] 
1512             except HttpError, e: 
1513                 start_response(e.status, response.headers) 
1514                 return ['<html><body><h1>', e.status, '</h1></body></html>'] 
1515             except Exception, e: 
1516                 logging.exception(e) 
1517                 if not debug: 
1518                     start_response('500 Internal Server Error', []) 
1519                     return ['<html><body><h1>500 Internal Server Error</h1></body></html>'] 
1520                 exc_type, exc_value, exc_traceback = sys.exc_info() 
1521                 fp = StringIO() 
1522                 traceback.print_exception(exc_type, exc_value, exc_traceback, file=fp) 
1523                 stacks = fp.getvalue() 
1524                 fp.close() 
1525                 start_response('500 Internal Server Error', []) 
1526                 return [ 
1527                     r'''<html><body><h1>500 Internal Server Error</h1><div style="font-family:Monaco, Menlo, Consolas, 'Courier New', monospace;"><pre>''', 
1528                     stacks.replace('<', '&lt;').replace('>', '&gt;'), 
1529                     '</pre></div></body></html>'] 
1530             finally: 
1531                 del ctx.application 
1532                 del ctx.request 
1533                 del ctx.response 
1534 
 
1535         return wsgi 
1536 
 
1537 if __name__=='__main__': 
1538     sys.path.append('.') 
1539     import doctest 
1540     doctest.testmod() 
 


 
   

