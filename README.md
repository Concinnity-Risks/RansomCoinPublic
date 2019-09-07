# RansomCoin
Extracting metadata and hardcoded Indicators of Compromise from ransomware, in a scalable, efficient, way with cuckoo integrations. Ideally, is it run during cuckoo dynamic analysis, but can also be used for static analysis on large collections of ransomware. Designed to be fast, with low false positive for cryptocurrency addresses. Limited false positives for emails, urls, onions, and domains (which is pretty hard to make perfect). 

In short, this is fast and easy initial triage if you only want monetisation vectors.

---Installation instructions---

From the tools folder:
```
sudo apt-get install build-essential libpoppler-cpp-dev pkg-config python-dev python3-tlsh
python3 -m pip install -r requirements.txt
```

---Usage instructions---

```
python3 coinlector.py
```

This will run the code across all files in the directoy and provide feedback on the estimated time to completion via TQDM. You will need write access for a file called Ransomware.csv in the directory you are working in (which contains the results). It should be possible to run the code across read only malware files though, so only Ransomware.csv need write access.

Currently we are testing for:
```
+Bitcoin Addresses
+Bitcoin Cash Addresses
+Monero Addresses
+Bitcoin Private Keys
+Ethereum addresses
+Ripple addresses
+LTC addresses
+DOGECOIN addresses
+NEO addresses
+DASH addresses
+Domains
+Email Addresses
+Onion Addresses
```
---Inventory---

+chaisingcoin.py gathers basic info on amounts recieved in BTC, by accounts gathered, based on the output of coinlector.py.

+eventcoin.py make IoCs of BTC addresses for a MISP instance, based on the output of coinlector.py. Can easily be extended to include other IoCs such as URLs or XMR accounts.

---Consider Donating---

We accept anonymous donations towards our software development on this project via a Monero address: 
82XYqsdEi6oCe2Rekg99pCjPxGCyJyNaA9m5R51LqDPgD1PGvS82YA9PUpPL3uXZf4ZZT2DnLBejKCXyk2YbmJUEB6FoTik

![A QR Code for donating to the software development](https://github.com/Concinnity-Risks/RansomCoinPublic/blob/master/RansomCoinMoneroDonationAddress.png)
