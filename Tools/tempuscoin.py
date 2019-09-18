#!/usr/bin/env python
# Copyleft 2019 Eireann Leverett of Concinnity Risks
#
# File name tempuscoin.py
# written by eireann.leverett@cantab.net
import requests
import json
import csv
from tqdm import tqdm
import sys
import time
import datetime

converter = 'https://min-api.cryptocompare.com/data/pricehistorical?fsym=BTC&tsyms=USD,EUR&ts='
converter_rls = 'https://min-api.cryptocompare.com/stats/rate/limit'
g_rate_limit = 300
start_time = time.time()
now = time.time()
s_in = {'BTC': 0, 'EUR': 0, 'USD': 0}
s_out = {'BTC': 0, 'EUR': 0, 'USD': 0}
n_tx = 0
i = 0
btc = None
jreq = None

try:
    conversion_rates = json.load(open("conversion_rates_dump.txt"))
except:
    conversion_rates = {}

def get_consumption(output=False):
    global jreq
    try:
        req = requests.get(converter_rls)
        jreq = req.json()
        minute = str(jreq['Data']['calls_left']['minute'])
        hour   = str(jreq['Data']['calls_left']['hour'])
    except:
        minute = str(-1)
        hour = str(-1)
    if output is True:
        print("Calls left this minute / hour: " + minute + " / " + hour)
    return minute, hour


def convert(btc, timestamp):
    global g_rate_limit
    global start_time
    global now
    global conversion_rates
    date = time.strftime('%Y-%m-%d', time.localtime(timestamp))
    # Lookup conversion rates in the cache:
    if date in conversion_rates:
        (usd, eur) = conversion_rates[date]
    else:
        # If not cached, we have to get the conversion rates
        # We have to be careful with rate limiting on the server side
        if g_rate_limit == 300:
            minute, hour = get_consumption()
        g_rate_limit -= 1
        now = time.time()
        delta = now - start_time
        #print(g_rate_limit)
        if g_rate_limit <= 10:
            minute, hour = get_consumption(output=True)
            if int(minute) <= 10:
                time.sleep(3)
            else:
                print(minute)
                start_time = time.time()
                g_rate_limit = int(minute)
        try:
            req = requests.get(converter+str(timestamp))
            jreq = req.json()
            usd = jreq['BTC']['USD']
            eur = jreq['BTC']['EUR']
            # Since we have the rates, add them to the cache
            conversion_rates[date] = (usd, eur)
        except Exception as ex:
            print(ex)
            get_consumption(output=True)
    # Actually convert and return the values
    u = usd * btc
    e = eur * btc
    return u,e

LIST_OF_ADDRESSES = []

if len(sys.argv) < 0:
    with open(sys.argv[1], 'r') as inputfile:
        #We assume it is a text file with BTC addresses on each line
        for line in inputfile:
            LIST_OF_ADDRESSES.append(line)
else:
    with open('Ransomware.csv', 'r') as inputfile:
        coinreader = csv.reader(inputfile, delimiter=',',)
        for row in coinreader:
            if row[6] == 'BTC Address':
                LIST_OF_ADDRESSES.append(row[7])
inputfile.close()

# deduplicate the list
LIST_OF_ADDRESSES = list(set(LIST_OF_ADDRESSES))

#print(LIST_OF_ADDRESSES)
#The goal of this code is to display the temporal nature of payments
with open('TemporalRansoms.csv', 'w') as csvfile:
    RESULTS_WRITER = csv.writer(
        csvfile,
        delimiter=',',
        quotechar='"',
        quoting=csv.QUOTE_MINIMAL)
    RESULTS_WRITER.writerow(['sending_address',
                             'receiving_address',
                             'time',
                             'BTC','EUR','USD'])
    for ADDRESS in tqdm(LIST_OF_ADDRESSES):
        s = requests.Session()
        s.auth = ('concinnity@cantab.net', '3158ef3d-593d-4c36-9c3f-c1ac5c1effda')
        try:
            with s.get('https://blockchain.info/rawaddr/' + ADDRESS, stream=True) as result:
                if result.status_code == 200:
                    data = result.json()
                    for tx in data['txs']:
                        for input in tx['inputs']:
                            conversions = convert(input['prev_out']['value']/100000000.00,int(tx['time']))
                            RESULTS_WRITER.writerow([input['prev_out']['addr'],
                                                    ADDRESS,
                                                    datetime.datetime.fromtimestamp(int(tx['time'])),
                                                    input['prev_out']['value']/100000000.00,
                                                    '{0:.2f}'.format(conversions[1]).rstrip('0'),
                                                    '{0:.2f}'.format(conversions[0]).rstrip('0')])
                else:
                    print('HTTP Response is: ' + str(result.status_code))
                    time.sleep(3)
        except Exception as E:
            print(E)
            time.sleep(3)
csvfile.close()
