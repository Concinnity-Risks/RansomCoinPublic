# RansomCoin
Extracting metadata and hardcoded Indicators of Compromise from ransomware, in a scalable, efficient, way with cuckoo integrations. Ideally, is run during cuckoo dynamic analysis, on folders where changes occur, but can also be used for static analysis on large collections of ransomware. 

From the tools folder:
pip install -r requirements.txt

After that: python coinlector.py will run the code across all files in the directoy and provide feedback on the ETC.

Currently we are testing for:
+Bitcoin Addresses
+Monero Addresses
+Bitcoin Cash Address
+Domains
+Email Addresses
+Onion Addresses

chaisingcoin.py gathers basic info on amounts recieved in BTC, by accounts gathered, based on the output of coinlector.py.
eventcoin.py make IoCs of BTC addresses for a MISP instance, based on the output of coinlector.py. Can easily be extended to include other IoCs such as URLs or XMR accounts.
