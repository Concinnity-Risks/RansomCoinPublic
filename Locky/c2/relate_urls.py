from __future__ import print_function
import os, json
from scapy.all import *

path_base = "/home/pete/.cuckoo_locky/storage/analyses/"
f_urls = open("/home/pete/scripts/locky_domains","r").readlines()
results = {}
for u in f_urls:
    u = u.strip('\n\r ')
    results[u] = {}

for index,d in enumerate(os.listdir(path_base)):
    print("\nProcessing analysis %s (%d of %d)" % (d, index, len(os.listdir(path_base))))
    packets = rdpcap(path_base + d + "/dump.pcap")
    for packet in packets:
        if packet.haslayer(DNSRR):
            packet_dns = packet[DNSRR].rrname.strip('\n\r ')
            for index2,url in enumerate(f_urls):
                print(("\tChecking URLs - %d/%d" % (index2,len(f_urls))).ljust(100), end='\r')
                url = url.strip('\n\r ')
                if url in packet_dns:
                    url_sources = {}
                    report = json.loads(open(path_base + d + "/reports/report.json","r").read())
                    if report['target']['category'] == "file":
                        url_sources[d] = report['target']['file']['name']
                    elif report['target']['category'] == "archive":
                        url_sources[d] = report['target']['archive']['name']
                    results[url].update(url_sources)

# Print
logfile = open(os.getcwd() + "/linked_urls.json","w")
results_json = json.dumps(results)
logfile.write(results_json)
logfile.close()

for k,v in results.items():
    print("\n%s\t%s" % (k,v))
