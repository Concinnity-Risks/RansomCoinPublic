#!/usr/bin/env python
# Copyleft 2018 Eireann Leverett of Concinnity Risks
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
# File name coinlector.py
# written by eireann.leverett@cantab.net

import os
import re
import csv
import hashlib
import base58
import mmap
from monero.address import address
from tqdm import tqdm

# Useful vars
chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
shortest_run = 6

regexp = '[%s]{%d,}' % (chars, shortest_run)
pattern = re.compile(regexp)

# Address Validation checks


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


def validate_xmr_address(xmr_address):
    try:
        # assign an address and see if it creates an error (quick and dirty
        # address validation)
        a = address(xmr_address)
        return True
    except BaseException:
        return False
# Section for regexes we're interested in


# URLs
url = re.compile(
    "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
# Onion addresses
onion = re.compile("(?:https?://)|(?:http?://)?(?:www)?(\S*?\.onion)\b")

# Crypto currency addresses, bank accounts, and pay ids
btc_priv_key = re.compile("5[HJK][1-9A-Za-z][^OIl]{48}")
btcorbch = re.compile(
    "([13][a-km-zA-HJ-NP-Z1-9]{25,34})|((bitcoincash:)?(q|p)[a-z0-9]{41})|((BITCOINCASH:)?(Q|P)[A-Z0-9]{41})")
xmr = re.compile("4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}")

# email
email = re.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

try:
    os.remove('Ransomware.csv')
except OSError:
    pass

# This variable just helps us track how many malware files we have
# potential Monetisation IoCs for
CoinsCollected = 0

with open('Ransomware.csv', 'wb') as csvfile:
    resultswriter = csv.writer(
        csvfile,
        delimiter=',',
        quotechar='"',
        quoting=csv.QUOTE_MINIMAL)
    resultswriter.writerow(['md5',
                            'sha1',
                            'sha256',
                            'filename',
                            'Class of Observable',
                            'Potential Monetisation Vector'])
    for filename in tqdm(os.listdir(os.getcwd())):
        if filename == 'Ransomware.csv' or filename == 'coinlector.py':
            pass
        else:
            with open(filename, mode='r+b') as f:
                openedFile = open(filename)
                readFile = openedFile.read()
                md5 = hashlib.md5(readFile).hexdigest()
                sha1 = hashlib.sha1(readFile).hexdigest()
                sha256 = hashlib.sha256(readFile).hexdigest()
                openedFile.close()
                CoinCollected = False
                data = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
                for match in url.finditer(data):
                    resultswriter.writerow(
                        [md5, sha1, sha256, filename, "URL", match])

                    if onion.search(match.group(0)) and CoinCollected == False:
                        CoinCollected = True
                for match in btc_priv_key.finditer(data):
                    if b58decode_check(match.group(0)):
                        resultswriter.writerow([md5,
                                                sha1,
                                                sha256,
                                                filename,
                                                "Bitcoin Private Key",
                                                match.group(0)])
                    if not CoinCollected:
                        CoinCollected = True
                for match in xmr.finditer(data):
                    if validate_xmr_address(match.group(0)):
                        resultswriter.writerow(
                            [md5, sha1, sha256, filename, "XMR Address", xmr.search(data).group(0)])
                        if not CoinCollected:
                            CoinCollected = True
                for match in email.finditer(data):
                    resultswriter.writerow(
                        [md5, sha1, sha256, filename, "Email Address", match.group(0)])
                    if not CoinCollected:
                        CoinCollected = True
                # This one needs to be near the bottom, as it matches
                # shorter base58 strings
                for match in btcorbch.finditer(data):
                    if b58decode_check(match.group(0)):
                        resultswriter.writerow(
                            [md5, sha1, sha256, filename, "BTC/BCH Address", match.group(0)])
                    if not CoinCollected:
                        CoinCollected = True
            f.close()
            if CoinCollected:
                CoinsCollected += 1
csvfile.close()
print "Yield ratio is: " + \
    str(100 * CoinsCollected / len(os.listdir(os.getcwd()))) + "%\n"
