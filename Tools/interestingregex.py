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

import os.path
import sys
import re

chars = r"A-Za-z0-9/\-:.,_$%'()[\]<> "
shortest_run = 4

regexp = '[%s]{%d,}' % (chars, shortest_run)
pattern = re.compile(regexp)

def process(stream):
    data = stream.read()
    return pattern.findall(data)

file = "testransomware"
accountnos = []

#Crypto currency addresses and pay ids
btc = re.compile("5[HJK][1-9A-Za-z][^OIl]{48}")
bch = re.compile("([13][a-km-zA-HJ-NP-Z1-9]{25,34})|((bitcoincash:)?(q|p)[a-z0-9]{41})|((BITCOINCASH:)?(Q|P)[A-Z0-9]{41})")
xmr = re.compile("4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}")
xmrpayid = re.compile("[0-9a-fA-F]{16}|[0-9a-fA-F]{64}")
#Onion addresses
onion = re.compile("(?:https?://)|(?:http?://)?(?:www)?(\S*?\.onion)\b")
#email
email = re.compile("[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+")
with open(file) as f:
    for line in process(f):
        if btc.search(line):
            print "Bitcoin Address Found"
            print line
        elif  xmr.search(line):
            print "Monero Address Found"
            print line
        elif email.search(line):
            print "Email Address Found"
            print line
        elif onion.search(line):
            print "Onion Address Found"
            print line
        #This one needs to be near the bottom, as it matches shorter base58 strings
        elif  bch.search(line):
            print "Bitcoin Cash Address Found"
            print line
        #This one needs to be last, as it basically matches domains and emails
        elif xmrpayid.search(line):
            print "Monero Pay ID Found"
            print line
        else:
            pass
