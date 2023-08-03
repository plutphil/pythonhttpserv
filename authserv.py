# Extended python -m http.serve with --username and --password parameters for
# basic auth, based on https://gist.github.com/fxsjy/5465353

from functools import partial
from http.server import SimpleHTTPRequestHandler, test
import http.cookies
import base64
import os
import ssl
import http.server
from urllib.parse import urlparse, parse_qs
import urllib
def pwgen(length=6):
    import string
    import secrets
    import random
    symbols = list("+-.,") # Can add more

    password = ""
    for _ in range(length):
        password += secrets.choice(string.ascii_lowercase)
    password += secrets.choice(string.ascii_uppercase)
    password += secrets.choice(string.digits)
    password += secrets.choice(symbols)
    return ''.join(random.sample(password,len(password)))
class AuthHTTPRequestHandler(SimpleHTTPRequestHandler):
    """ Main class to present webpages and authentication. """

    def __init__(self, *args, **kwargs):
        username = kwargs.pop("username")
        password = kwargs.pop("password")
        self.logintoken = kwargs.pop("logintoken")
        self._auth = base64.b64encode(f"{username}:{password}".encode()).decode()
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

    def do_AUTHHEAD(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="Test"')
        self.send_header("Content-type", "text/html")
        self.end_headers()
    def sendCookie(self):
        cookie = http.cookies.SimpleCookie()
        cookie['token'] = self.logintoken
        self.send_response(200)
        self.send_header("Set-Cookie", cookie.output(header='', sep=''))
        self.send_header("Content-type", "text/html")
    def do_GET(self):
        """ Present frontpage with user authentication. """
        print(os.path.basename(urlparse(self.path).path))
        if(os.path.basename(urlparse(self.path).path)=="private.key"):
            self.send_response(405)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(b"405 Method Not Allowed")
            return
        query_components = parse_qs(urlparse(self.path).query)
        print(query_components)
        if "t" in query_components:
            token = query_components["t"][0]
            if(token==self.logintoken):
                self.sendCookie()
                SimpleHTTPRequestHandler.do_GET(self)
                return
            else:
                self.do_HEAD()
                self.wfile.write(b"token not valid!")
                return

        if "user-agent" in self.headers:
            print(self.headers["user-agent"],end="",flush=True)
        if "Cookie" in self.headers:
            cookies = http.cookies.SimpleCookie(self.headers.get('Cookie'))
            if(cookies['token'].value==self.logintoken):
                self.sendCookie()
                SimpleHTTPRequestHandler.do_GET(self)
                return
        if self.headers.get("Authorization") == None:
            self.do_AUTHHEAD()
            self.wfile.write(b"no auth header received")
        elif self.headers.get("Authorization") == "Basic " + self._auth:
            SimpleHTTPRequestHandler.do_GET(self)
        else:
            self.do_AUTHHEAD()
            self.wfile.write(self.headers.get("Authorization").encode())
            self.wfile.write(b"not authenticated")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--cgi", action="store_true", help="Run as CGI Server")
    import getlanip
    parser.add_argument(
        "--bind",
        "-b",
        metavar="ADDRESS",
        default=getlanip.getlanip(),
        help="Specify alternate bind address " "[default: all interfaces]",
    )
    parser.add_argument(
        "--directory",
        "-d",
        default=os.getcwd(),
        help="Specify alternative directory " "[default:current directory]",
    )
    parser.add_argument(
        "--nossh",
        "-s",
        default=False,
        help="disable ssh",
    )
    parser.add_argument(
        "port",
        action="store",
        default=8000,
        type=int,
        nargs="?",
        help="Specify alternate port [default: 8000]",
    )
    parser.add_argument("--username", "-u", metavar="USERNAME",default="user")
    parser.add_argument("--password", "-p", metavar="PASSWORD",default=pwgen())
    _logintoken = pwgen(10)
    args = parser.parse_args()
    print("user:",args.username)
    print("password:",args.password)
    import os,os.path,sys
    if not os.path.exists("private.key"):
        import gencert
        gencert.cert_gen()
    handler_class = partial(
        AuthHTTPRequestHandler,
        username=args.username,
        password=args.password,
        directory=args.directory,
        logintoken=_logintoken
    )
    
    with http.server.HTTPServer((args.bind, args.port), handler_class) as httpd:
        prot = "http://"
        if(args.nossh==False):
            sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            sslcontext.load_cert_chain(keyfile="private.key", certfile="selfsigned.crt")
            httpd.socket = sslcontext.wrap_socket(httpd.socket, server_side=True)
            prot = "https://"
        from urllib.parse import quote_plus
        url = prot+args.bind + ":" + str(args.port) + "?t="+quote_plus(_logintoken)
        
        from asciiqr import printqrcode
        printqrcode(url)
        print("Web Server listening at => "+url)
        
        for i in getlanip.getlanips():
            url = prot+i + ":" + str(args.port) + "?t="+quote_plus(_logintoken)
            print(url)
        for i in getlanip.getlanipsv6():
            url = prot+"["+i+"]" + ":" + str(args.port) + "?t="+quote_plus(_logintoken)
            print(url)
        def th():
            import time
            import ssl
            import urllib.request
            time.sleep(1)
            ssl._create_default_https_context = ssl._create_unverified_context
            for i in getlanip.getlanips():
                url = prot+i + ":" + str(args.port) + "?t="+quote_plus(_logintoken)
                try:
                    res = urllib.request.urlopen(url)
                    print(url,res.status)
                except Exception as e:
                    #print(url,e)
                    pass
            pass
        import threading
        threading.Thread(target=th).start()
        httpd.serve_forever()
    
        
