#!/usr/bin/env python
# Copyright 2018 Eireann Leverett of Concinnity Risks
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.*)
#
# File name interestingregex.py
# written by eireann.leverett@cantab.net

from tqdm import *
import os
import sys
import re
import csv
import hashlib
import base58

#Useful Functions

chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
shortest_run = 6

regexp = '[%s]{%d,}' % (chars, shortest_run)
pattern = re.compile(regexp)

def process(stream):
    data = stream.read()
    return pattern.findall(data)

#Address Validation

def b58decode_check(potential_address):
    '''Decode and verify the checksum of a Base58 encoded string'''
    try:
        result = base58.b58decode(potential_address)
        result, check = result[:-4], result[-4:]
        digest = hashlib.sha256(hashlib.sha256(result).digest()).digest()
    except ValueError:
        return False
    if check != digest[:4]:
        return False
    else:
        return True

#Section for regexes we're interested in

#URLs
url = re.compile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")

#Crypto currency addresses and pay ids
btc_priv_key = re.compile("5[HJK][1-9A-Za-z][^OIl]{48}")
btcorbch = re.compile("([13][a-km-zA-HJ-NP-Z1-9]{25,34})|((bitcoincash:)?(q|p)[a-z0-9]{41})|((BITCOINCASH:)?(Q|P)[A-Z0-9]{41})")
xmr = re.compile("4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}")
xmrpayid = re.compile("[0-9a-fA-F]{16}|[0-9a-fA-F]{64}")
#Onion addresses DEPRECATED
#onion = re.compile("(?:https?://)|(?:http?://)?(?:www)?(\S*?\.onion)\b")
#email
email = re.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

#The main body of code
with open('Ransomware.csv', 'wb') as csvfile:
    resultswriter = csv.writer(csvfile, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
    resultswriter.writerow(['md5','sha1','sha256','filename','Class of Observable','Address'])
    for filename in tqdm(os.listdir(os.getcwd())):
        with open(filename, 'rb') as f:
            openedFile = open(filename)
            readFile = openedFile.read()
            md5 = hashlib.md5(readFile).hexdigest()
            sha1 =  hashlib.sha1(readFile).hexdigest()
            sha256 =  hashlib.sha256(readFile).hexdigest()
            openedFile.close()
            for line in tqdm(process(f)):
                if url.search(line):
                    resultswriter.writerow([md5,sha1,sha256,filename,"URL",url.search(line).group(0)])
                elif btc_priv_key.search(line) and b58decode_check(btc_priv_key.search(line).group(0)) == True:
                    resultswriter.writerow([md5,sha1,sha256,filename,"Bitcoin Private Key",btc_priv_key.search(line).group(0)])
                elif xmr.search(line):
                    resultswriter.writerow([md5,sha1,sha256,filename,"XMR Address",xmr.search(line).group(0)])
                elif email.search(line):
                    resultswriter.writerow([md5,sha1,sha256,filename,"Email Address",email.search(line).group(0)])
                #This one needs to be near the bottom, as it matches shorter base58 strings
                elif btcorbch.search(line) and b58decode_check(btcorbch.search(line).group(0)) == True:
                    resultswriter.writerow([md5,sha1,sha256,filename,"BTC/BCH Address",btcorbch.search(line).group(0)])
                #This one needs to be last, as it basically matches domains and emails too
                elif xmrpayid.search(line):
                    resultswriter.writerow([md5,sha1,sha256,filename,"XMR Pay ID",xmrpayid.search(line).group(0)])
                else:
                    pass
        f.close()
csvfile.close()
