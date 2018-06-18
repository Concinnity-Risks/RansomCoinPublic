import os

log = open("/home/pete/scripts/logs/http.txt","r")

contents = log.readlines()

for i,l in enumerate(contents):
    if l.startswith("Host"):
        request_get = l.split()[1]
        #done = False
        #c = 0
        #while not done:
        #    line = contents[i+c]
        #    if line.startswith("Host"):
        #        request_host = line.split()[1]
        #        done = True
        #    else:
        #        c += 1
        
        #print "%s%s" % (request_host,request_get)
        print request_get
