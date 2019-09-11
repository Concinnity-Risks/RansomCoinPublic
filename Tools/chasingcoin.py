#!/usr/bin/env python
# Copyleft 2018 Eireann Leverett of Concinnity Risks
#
#
# File name chasingcoin.py
# written by eireann.leverett@cantab.net
import requests
import json
import csv
from tqdm import tqdm

LIST_OF_ADDRESSES = []
BATCH = ''

with open('Ransomware.csv', 'r') as inputfile:
    coinreader = csv.reader(inputfile, delimiter=',',)
    for row in coinreader:
        if row[6] == 'BTC Address':
            LIST_OF_ADDRESSES.append(row[7])
inputfile.close()

# deduplicate the list
LIST_OF_ADDRESSES = list(set(LIST_OF_ADDRESSES))


print(LIST_OF_ADDRESSES)
with open('AccountsRecievingRansom.csv', 'w') as csvfile:
    RESULTS_WRITER = csv.writer(
        csvfile,
        delimiter=',',
        quotechar='"',
        quoting=csv.QUOTE_MINIMAL)
    RESULTS_WRITER.writerow(['wallet',
                             'number of transactions',
                             'total BTC received',
                             'total BTC sent',
                             'final BTC balance'])
    for ADDRESS in tqdm(LIST_OF_ADDRESSES):
        #BATCH += ADDRESS + '|'
        result = requests.get('https://blockchain.info/rawaddr/' + ADDRESS)
        if result.status_code == 200:
            data = result.json()
            RESULTS_WRITER.writerow([data['address'],
                                     data['n_tx'],
                                     data['total_received']/100000000,
                                     data['total_sent']/1000000000,
                                     data['final_balance']/1000000000])
        else:
            print('HTTP Response is: ' + str(result.status_code))
csvfile.close()
#print json.dumps(result.json(), indent=4, sort_keys=True)
