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
'''Coinlector is a tool to autoextract common monetisation format Indicators of Compromise from ransomware binaries.'''
import os
import re
import csv
import hashlib
import mmap
import base58
from monero.address import address
from tqdm import tqdm

# Address Validation checks

def b58decode_check(potential_address):
    '''Decode and verify the checksum of a Base58 encoded string'''
    try:
        result = base58.b58decode(potential_address)
        result, check = result[:-4], result[-4:]
        digest = hashlib.sha256(hashlib.sha256(result).digest()).digest()
        return check == digest[:4]
    except ValueError:
        return False


def validate_xmr_address(xmr_address):
    '''Verify the checksum of a Monero address'''
    try:
        # assign an address and see if it creates an error
        address(xmr_address)
        return True
    except BaseException:
        return False

# Section for regexes of interest as Indicators of Compromise


# URLs
URL = re.compile(
    "http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
# ONION addresses
ONION = re.compile("(?:https?://)|(?:http?://)?(?:www)?(\S*?\.onion)\b")

# Crypto currency addresses, bank accounts, and pay ids
BTC_PRIV_KEY = re.compile("5[HJK][1-9A-Za-z][^OIl]{48}")
BTC_OR_BCH = re.compile(
    "([13][a-km-zA-HJ-NP-Z1-9]{25,34})|((bitcoincash:)?(q|p)[a-z0-9]{41})|((BITCOINCASH:)?(Q|P)[A-Z0-9]{41})")
XMR = re.compile("4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}")

# email
EMAIL = re.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

try:
    os.remove('Ransomware.csv')
except OSError:
    pass

# This variable just helps us track how many malware files we have
# potential Monetisation IoCs for
COINS_COLLECTED = 0

with open('Ransomware.csv', 'wb') as csvfile:
    RESULTS_WRITER = csv.writer(
        csvfile,
        delimiter=',',
        quotechar='"',
        quoting=csv.QUOTE_MINIMAL)
    RESULTS_WRITER.writerow(['md5',
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
                readFile = f.read()
                md5 = hashlib.md5(readFile).hexdigest()
                sha1 = hashlib.sha1(readFile).hexdigest()
                sha256 = hashlib.sha256(readFile).hexdigest()
                CoinCollected = False
                data = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
                for match in URL.finditer(data):
                    RESULTS_WRITER.writerow(
                        [md5, sha1, sha256, filename, "URL", match.group(0)])
                    if ONION.search(match.group(0)) and not CoinCollected:
                        CoinCollected = True
                #Yeah, I know...but imagine if we did find one...never underestimate how stupid...
                for match in BTC_PRIV_KEY.finditer(data):
                    if b58decode_check(match.group(0)):
                        RESULTS_WRITER.writerow([md5,
                                                 sha1,
                                                 sha256,
                                                 filename,
                                                 "Bitcoin Private Key",
                                                 match.group(0)])
                    if not CoinCollected:
                        CoinCollected = True
                for match in XMR.finditer(data):
                    if validate_xmr_address(match.group(0)):
                        RESULTS_WRITER.writerow(
                            [md5, sha1, sha256, filename, "XMR Address", match.group(0)])
                        if not CoinCollected:
                            CoinCollected = True
                for match in EMAIL.finditer(data):
                    RESULTS_WRITER.writerow(
                        [md5, sha1, sha256, filename, "Email Address", match.group(0)])
                    if not CoinCollected:
                        CoinCollected = True
                for match in BTC_OR_BCH.finditer(data):
                    if b58decode_check(match.group(0)):
                        RESULTS_WRITER.writerow(
                            [md5, sha1, sha256, filename, "BTC/BCH Address", match.group(0)])
                    if not CoinCollected:
                        CoinCollected = True
            f.close()
            if CoinCollected:
                COINS_COLLECTED += 1
    RESULTS_WRITER.writerow(["Yield ratio is: " + str(100 * COINS_COLLECTED / len(os.listdir(os.getcwd()))) + "%"," Across",len(os.listdir(os.getcwd())),"samples","","","End of File"])
    csvfile.close()
