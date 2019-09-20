#!/usr/bin/env python
# Copyleft 2018 Eireann Leverett of Concinnity Risks
#
# File name coinlector.py
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
import sha3
import tlsh
import magic
import pdftotext
import monero
from binascii import hexlify,unhexlify
#Not strictly needed, but shows progress bar on large sample sets
from tqdm import tqdm

# Address Validation checks
#All THIS SHOULD BE REFACTORED TO BE PASS IN THE TICKER AFTER THE REGEX SUCCEEDS
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

def xrp_verify( xrp_match ):
    '''Decode and verify a Ripple address'''
    try:
        return coinaddr.validate('xrp', xrp_match)
    except TypeError:
        return False
    except ValueError:
        return False

def ltc_verify( ltc_match ):
    '''Decode and verify a Litecoin address'''
    try:
        return coinaddr.validate('ltc', ltc_match)
    except TypeError:
        return False
    except ValueError:
        return False

def doge_verify( doge_match ):
    '''Decode and verify a Dogecoin address'''
    try:
        return coinaddr.validate('doge', doge_match)
    except TypeError:
        return False
    except ValueError:
        return False

def neo_verify( neo_match ):
    '''Decode and verify a Neocoin address'''
    try:
        return coinaddr.validate('neo', neo_match)
    except TypeError:
        return False
    except ValueError:
        return False

def xmr_verify( xmr_match ):
    try:
        pubAddrHex = monero.base58.decode(xmr_match.decode("utf8"))
        pubAddrChksum = pubAddrHex[-8:]
        pubAddrForHash = pubAddrHex[:-8]
        #print(pubAddrChksum)
        #print(pubAddrForHash)
        k = sha3.keccak_256()
        k.update(unhexlify(pubAddrForHash))
        pubAddrHash = k.hexdigest()
        pubAddrChksum2 = pubAddrHash[:8]
        if pubAddrChksum2 == pubAddrChksum:
            #print("True: %s" % xmr_match)
            return True
        else:
            #print("False: %s" % xmr_match)
            return False
    except Exception as E:
        #print("Exception: %s" % E)
        return False

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
XRP = re.compile(b"r[0-9a-zA-Z]{24,34}")
LTC = re.compile(b"[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}")
DOGE = re.compile(b"D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}")
NEO = re.compile(b"A[0-9a-zA-Z]{33}")
XMR = re.compile(b"4[0-9AB][0-9a-zA-Z]{93,104}")

# email
EMAIL = re.compile(b"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")

try:
    os.remove('Ransomware.csv')
except OSError:
    pass

# This variable just helps us track how many malware files we have
# potential Monetisation IoCs for
COINS_COLLECTED = 0

#This variable helps us get our yield callculations correct
FILES_WE_PRODUCE = 0

with open('Ransomware.csv', 'w') as csvfile:
    RESULTS_WRITER = csv.writer(
        csvfile,
        delimiter=',',
        quotechar='"',
        quoting=csv.QUOTE_MINIMAL)
    RESULTS_WRITER.writerow(["tlsh","md5","sha1","sha256","filename","filetype","Class of Observable","Potential Monetisation Vector"])
    for filename in tqdm(os.listdir(os.getcwd())):
        #Don't analyse any of the files we produce/use
        if filename == 'Ransomware.csv' or filename == 'coinlector.py' or filename == 'AccountsRecievingRansom.csv' or filename == 'chasingcoin.py' or filename == 'eventcoin.py' or 'TemporalRansoms.csv' or os.path.isdir(filename):
            FILES_WE_PRODUCE += 1
            pass
        else:
            try:
                filetype = magic.from_file(filename)
                #Strip the commas from the strings so we don't break our own csv output formatting
                filetype = filetype.replace(',', '')
                with open(filename, mode='rb') as f:
                    if 'PDF document' in filetype:
                        try:
                            pdf = pdftotext.PDF(f)
                            readFile = bytes("\n\n".join(pdf),'UTF-8')
                        except:
                            readFile = f.read()
                    else:
                        readFile = f.read()
                    tlshash = tlsh.hash(readFile)
                    md5 = hashlib.md5(readFile).hexdigest()
                    sha1 = hashlib.sha1(readFile).hexdigest()
                    sha256 = hashlib.sha256(readFile).hexdigest()
                    CoinCollected = False
                    RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "NONE", "Analysed"])
                    try:
                        if 'PDF document' in filetype:
                            data = readFile
                        else:
                            data = mmap.mmap(f.fileno(), 0, prot=mmap.PROT_READ)
                        for match in URL.finditer(data):
                            RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "URL", match.group(0).decode("utf-8")])
                            if ONION.search(match.group(0)) and not CoinCollected:
                                CoinCollected = True
                        for match in BTC_PRIV_KEY.finditer(data):
                            if b58decode_check(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5,
                                                         sha1,
                                                         sha256,
                                                         filename,
                                                         filetype,
                                                         "Bitcoin Private Key",
                                                         match.group(0).decode("utf-8")])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in XMR.finditer(data):
                            if xmr_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "XMR Address", match.group(0).decode("utf-8")])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in EMAIL.finditer(data):
                            RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "Email", match.group(0).decode("utf-8")])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in BTC.finditer(data):
                            if btc_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "BTC Address", match.group(0).decode("utf-8")])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in BCH.finditer(data):
                            if bch_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "BCH Address", match.group(0).decode("utf-8") ])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in DASH.finditer(data):
                            if dash_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "DASH Address", match.group(0).decode("utf-8") ])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in ETH.finditer(data):
                            if eth_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "ETH/ETC/ETZ Address", match.group(0).decode("utf-8") ])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in LTC.finditer(data):
                            if ltc_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "LTC Address", match.group(0).decode("utf-8") ])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in NEO.finditer(data):
                            if neo_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "NEO Address", match.group(0).decode("utf-8") ])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in DOGE.finditer(data):
                            if doge_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "DOGE Address", match.group(0).decode("utf-8") ])
                            if not CoinCollected:
                                CoinCollected = True
                        for match in XRP.finditer(data):
                            if xrp_verify(match.group(0)):
                                RESULTS_WRITER.writerow([tlshash, md5, sha1, sha256, filename, filetype, "XRP Address", match.group(0).decode("utf-8") ])
                            if not CoinCollected:
                                CoinCollected = True
                    #An empty file crashes mmap, so we skip it to continue analysis
                    except ValueError:
                        pass
                f.close()
            except PermissionError:
                print("Some files are beyond the permissions of your user.")
                pass
            if CoinCollected:
                COINS_COLLECTED += 1
    RESULTS_WRITER.writerow(["Yield ratio is: " +
                             str(100 *
                                COINS_COLLECTED /
                                (len(os.listdir(os.getcwd()))-FILES_WE_PRODUCE)) +
                             "%", " Across", len(os.listdir(os.getcwd()))-FILES_WE_PRODUCE, "samples", "", "", "End of File"])
    csvfile.close()
