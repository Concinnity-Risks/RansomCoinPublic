#!/usr/bin/python

import socket, sys, os, argparse, time, datetime

class Logger(object):
    def __init__(self):
        if not os.path.exists("logs"):
            os.mkdir("logs")

        self.fo = open("logs/http.txt","a")

    def log(self, msg):
        stringtowrite = msg + "\r\n"
        self.fo.write(stringtowrite)
        print msg

    def close(self):
        self.fo.close()

class WebServer(object):
    def __init__(self, rootpath, portno, servefiles, host):
        self.logger = Logger()
        print "HTTP logs opened"
        self.WEBROOT = rootpath
        self.HOST, self.PORT = host, portno
        self.SERVEFILES = servefiles

    def createSocket(self):
        self.SERVER_SOCKET = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.SERVER_SOCKET.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.SERVER_SOCKET.bind((self.HOST, self.PORT))
        self.SERVER_SOCKET.listen(1)
        print "Listening for HTTP connections on port %s from the directory %s" % (self.PORT, self.WEBROOT)
        self.serveHTTP()

    def serveHTTP(self):
        while True:
            try:
                self.client_conn, self.client_addr = self.SERVER_SOCKET.accept()
                self.handleConnection()
            except KeyboardInterrupt:
                self.cleanup()
                break

    def handleConnection(self):
        self.request_data = self.client_conn.recv(1024)
        self.logger.log("TIME::" + datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S'))
        self.parseRequest()
        self.sendResponse()

    def parseRequest(self):
        if len(self.request_data) > 0:
            try:
                http_line = self.request_data.splitlines()[0]
                http_line = http_line.rstrip("\r\n")
                self.request_method, self.request_path, self.request_version = http_line.split()
                self.logger.log("REQUEST::" + self.request_data)
            except:
                self.logger.log("REQUEST::NO DATA")
        else:
            self.logger.log("REQUEST::NO DATA")

    def sendResponse(self):
        if self.SERVEFILES:
            if self.request_method == "GET":
                response_body = "<!DOCTYPE html><html><head><title>404 Page Not Found!</title></head><body><h1>Sorry!</h1><p>The requested page couldn't be found. Please check the URL and try again</p></body></html>"
                self.response_code = "404 Not Found"
                response = "HTTP/1.1 %s\r\n" % (self.response_code)
                response += "\r\n"
                response += response_body
                self.client_conn.sendall(response)
                self.logger.log("RESPONSE::" + self.response_code + "\n\n")
                self.client_conn.close()

    def cleanup(self):
        print "\nCaught CTRL+C - shutting down...."
        self.logger.close()
        self.SERVER_SOCKET.shutdown(socket.SHUT_RDWR)
        self.SERVER_SOCKET.close()

    def main(self):
        self.createSocket()


if __name__ == "__main__":
    WEB_ROOT = os.getcwd() + "/"
    PORT = 80
    SERVE_FILES = True
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-w","--webroot", help="Set the directory to serve files from. Defaults to the current directory for the script")
    argparser.add_argument("-p", "--port", help="Set the port to server HTTP over. Defaults to 80", type=int)
    argparser.add_argument("-x", "--nofile", help="Only server 404 error responses to requests", action="store_true")
    argparser.add_argument("-H", "--host", help="Local interface to bind to", default="0.0.0.0")
    args = argparser.parse_args()

    if args.webroot != None:
        WEB_ROOT = args.webroot
    if args.port != None:
        PORT = args.port
    if args.nofile != None:
        SERVE_FILES = False

    server = WebServer(WEB_ROOT, PORT, SERVE_FILES, args.host)
    server.main()
