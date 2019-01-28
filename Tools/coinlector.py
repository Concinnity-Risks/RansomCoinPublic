#!/usr/bin/env python
# Copyleft 2018 Eireann Leverett of Concinnity Risks
#
# File name coinlector3.py
# written by eireann.leverett@cantab.net
# Python 3 compatible version
'''Coinlector is a tool to autoextract common monetisation format Indicators of Compromise from ransomware binaries.'''
import os
import re
import csv
import hashlib
import mmap
import base58
import coinaddr
import cashaddress
#Might need these for future monero expansion
#Add to requirements when ready
import sha3
from binascii import hexlify, unhexlify
#Not strictly needed, but shows progress on large sample sets
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

def btc_verify( btc_match ):
    '''Decode and verify a Bitcoin address'''
    try:
        return coinaddr.validate('btc', btc_match)
    except TypeError:
        return False
    except ValueError:
        return False

def bch_verify( bch_match ):
    '''Decode and verify a Bitcoin Cash address'''
    print("Bitcoin Cash")
    print(bch_match)
    try:
        return cashaddress.convert.is_valid(bch_match.decode("utf-8"))
    except TypeError:
        return False
    except ValueError:
        return False

def dash_verify( dash_match ):
    '''Decode and verify a Dash address'''
    try:
        return coinaddr.validate('dash', dash_match)
    except TypeError:
        return False
    except ValueError:
        return False

def eth_verify( eth_match ):
    '''Decode and verify a Ethereum address'''
    try:
        return coinaddr.validate('eth', eth_match)
    except TypeError:
        return False
    except ValueError:
        return False

#def xmr_verify( xmr_match ):
#    '''Verify the checksum of a Monero address'''
#    print(xmr_match)
#    try:
#        decoded = bytearray(unhexlify(base58.b58decode(xmr_match)))
#        checksum = decoded[-4:]
#        if checksum == sha3.keccak_256(decoded[:-4]).digest()[:4]:
#            return True
#        else:
#            return False
#    except BaseException:
#        return False

# Section for regexes of interest as Indicators of Compromise


# URLs
URL = re.compile(b"http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")
# ONION addresses
ONION = re.compile(b"(?:https?://)|(?:http?://)?(?:www)?(\S*?\.onion)\b")

# Crypto currency addresses, bank accounts, and pay ids
BTC_PRIV_KEY = re.compile(b"5[HJK][1-9A-Za-z][^OIl]{48}")
BTC = re.compile(b"[13][a-km-zA-HJ-NP-Z1-9]{25,34}")
BCH = re.compile(b"(bitcoincash:)?(q|p)[a-z0-9]{41}|(BITCOINCASH:)?(Q|P)[A-Z0-9]{41}")
DASH = re.compile(b"X[1-9A-HJ-NP-Za-km-z]{33}")
ETH = re.compile(b"0x[a-fA-F0-9]{40}")
#XMR = re.compile(b"4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}")

# email
EMAIL = re.compile(b"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

try:
    os.remove('Ransomware.csv')
except OSError:
    pass

# This variable just helps us track how many malware files we have
# potential Monetisation IoCs for
COINS_COLLECTED = 0

with open('Ransomware.csv', 'w') as csvfile:
    RESULTS_WRITER = csv.writer(
        csvfile,
        delimiter=',',
        quotechar='"',
        quoting=csv.QUOTE_MINIMAL)
    RESULTS_WRITER.writerow(["md5","sha1","sha256","filename","Class of Observable","Potential Monetisation Vector"])
    for filename in tqdm(os.listdir(os.getcwd())):
        #Don't analyse any of the files we produce/use
        if filename == 'Ransomware.csv' or filename == 'coinlector.py' or filename == 'AccountsRecievingRansom.csv' or filename == 'chasingcoin.py' or filename == 'eventcoin.py' or os.path.isdir(filename):
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
                    RESULTS_WRITER.writerow([md5, sha1, sha256, filename, "URL", match.group(0).decode("utf-8")])
                    if ONION.search(match.group(0)) and not CoinCollected:
                        CoinCollected = True
                # Yeah, I know...but imagine if we did find one...never
                # underestimate how stupid...
                for match in BTC_PRIV_KEY.finditer(data):
                    if b58decode_check(match.group(0)):
                        RESULTS_WRITER.writerow([md5,
                                                 sha1,
                                                 sha256,
                                                 filename,
                                                 "Bitcoin Private Key",
                                                 match.group(0).decode("utf-8")])
                    if not CoinCollected:
                        CoinCollected = True
#                for match in XMR.finditer(data):
#                    if xmr_verify(match.group(0)):
#                        RESULTS_WRITER.writerow([md5, sha1, sha256, filename, "XMR Address", match.group(0).decode("utf-8")])
#                    if not CoinCollected:
#                        CoinCollected = True
                for match in EMAIL.finditer(data):
                    RESULTS_WRITER.writerow([md5, sha1, sha256, filename, "Email Address", match.group(0).decode("utf-8")])
                    if not CoinCollected:
                        CoinCollected = True
                for match in BTC.finditer(data):
                    if btc_verify(match.group(0)):
                        RESULTS_WRITER.writerow([md5, sha1, sha256, filename, "BTC Address", match.group(0).decode("utf-8")])
                    if not CoinCollected:
                        CoinCollected = True
                for match in BCH.finditer(data):
                    if bch_verify(match.group(0)):
                        RESULTS_WRITER.writerow([md5, sha1, sha256, filename, "BCH Address", match.group(0).decode("utf-8") ])
                    if not CoinCollected:
                        CoinCollected = True
                for match in DASH.finditer(data):
                    if dash_verify(match.group(0)):
                        RESULTS_WRITER.writerow([md5, sha1, sha256, filename, "DASH Address", match.group(0).decode("utf-8") ])
                    if not CoinCollected:
                        CoinCollected = True
                for match in ETH.finditer(data):
                    if eth_verify(match.group(0)):
                        RESULTS_WRITER.writerow([md5, sha1, sha256, filename, "ETH Address", match.group(0).decode("utf-8") ])
                    if not CoinCollected:
                        CoinCollected = True
            f.close()
            if CoinCollected:
                COINS_COLLECTED += 1
    RESULTS_WRITER.writerow(["Yield ratio is: " +
                             str(100 *
                                 COINS_COLLECTED /
                                 len(os.listdir(os.getcwd()))) +
                             "%", " Across", len(os.listdir(os.getcwd())), "samples", "", "", "End of File"])
    csvfile.close()
