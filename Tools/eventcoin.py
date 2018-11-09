
#!/usr/bin/env python
# Copyleft 2018 Eireann Leverett of Concinnity Risks
#
# File name eventcoin.py
# written by eireann.leverett@cantab.net
from pymisp import MISPEvent
from pymisp import PyMISP
import csv

# Your MISP's URL
url = ''

# The auth key to the MISP user that you wish to use. Make sure that the
# user has auth_key access
key = ''

# Should the certificate be validated?
ssl = True
misp = PyMISP(url, key, ssl)

csvfile = open("Ransomware.csv")
csvreader = csv.DictReader(csvfile)
lines = csvfile.readlines()
lasthash = ''
for line in lines:
    if "BTC/BCH" in line:
            attrs = line.split(",")
            if lasthash != attrs[3]:
                lasthash = attrs[3]
                event_obj = MISPEvent()
                event_obj.distribution = 1
                event_obj.threat_level_id = 3
                event_obj.analysis = 1
                event_obj.info = "RansomCoin Ransomware Survey "+attrs[3]
                event = misp.add_event(event_obj)
                event_id = event["Event"]["id"]
                print("Creating Event id: %s" % event_id)
                event_dict = misp.get(event_id)['Event']
                event = MISPEvent()
                event.from_dict(**event_dict)
                event.add_attribute(type='md5', category='Artifacts dropped', value=attrs[0], disable_correlation=False, to_ids=False, proposal=False, distribution=5)
                event.add_attribute(type='sha1', category='Artifacts dropped', value=attrs[1], disable_correlation=False, to_ids=False, proposal=False, distribution=5)
                event.add_attribute(type='sha256', category='Artifacts dropped', value=attrs[2], disable_correlation=False, to_ids=False, proposal=False, distribution=5)
                event.add_attribute(type='btc', category='Financial fraud', value=attrs[5], disable_correlation=False, to_ids=False, proposal=False, distribution=5)
            else:
                print("Adding to Event id: %s" % event_id)
                event_dict = misp.get(event_id)['Event']
                event = MISPEvent()
                event.from_dict(**event_dict)
                event.add_attribute(type='btc', category = 'Financial fraud', value=attrs[5], disable_correlation=False, to_ids=False, proposal=False, distribution=5)
            event_dict = misp.update(event)
csvfile.close()
