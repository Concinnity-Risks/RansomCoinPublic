# RansomCoin
Extracting metadata and hardcoded Indicators of Compromise from ransomware, in a scalable, efficient, way with cuckoo integrations. Ideally, is it run during cuckoo dynamic analysis, but can also be used for static analysis on large collections of ransomware. Designed to be fast, with low false positive for cryptocurrency addresses. Limited false positives for emails, urls, onions, and domains (which is pretty hard to make perfect). 

In short, this is fast and easy initial triage if you only want monetisation vectors.

## Installation instructions
Please ensure you have Python3 installed.

### In a Linux Virtual Machine 
It is advisable to download and install a virtualizer such as [VirtualBox](https://www.virtualbox.org/wiki/Downloads). Install your desired [Linux virtual machine](https://www.osboxes.org/virtualbox-images/) (i.e. Lubuntu, Kali Linux, etc) then follow the instructions below.

From the tools folder:
```
sudo apt-get install build-essential libpoppler-cpp-dev pkg-config python-dev python3-tlsh
```

```
python3 -m pip install -r requirements.txt
```

Note: If you get an error saying No module named pip, try running
```
sudo apt-get install python3-pip
```


## Usage instructions
A tutorial video is available: https://youtu.be/3pUDh5HvqVI

The following commands can be run from the "Tools" folder to analyse malware samples located in this directory. This will run the code across all files in the directoy and provide feedback on the estimated time to completion via TQDM. You will need write access for a file called Ransomware.csv in the directory you are working in (which contains the results). It should be possible to run the code across read only malware files though, so only Ransomware.csv need write access.


### Coinlector.py
After running coinlector.py the results are output to a file in the same directory called Ransomware.csv

```
python3 coinlector.py
```

View the results by running 

```
less Ransomware.csv
```

![Ransomware CSV](/Assets/Images/ransomware.png)

Currently we are testing for:

* Bitcoin Addresses (BTC)
* Bitcoin Cash Addresses (BCH)
* Monero Addresses (XMR)
* Bitcoin Private Keys 
* Ethereum addresses (ETH)
* Ripple addresses (XRP)
* LTC addresses (LTC)
* DOGECOIN addresses (DOGE)
* NEO addresses (NEO)
* DASH addresses (DASH)
* Domains (Address)
* Email Addresses (Email)
* Onion Addresses (Address)


View URLs, email addresses, and cryptocurrency addresses by running the following grep commands.

```
less Ransomware.csv | grep URL
```

```
less Ransomware.csv | grep Email
```

```
less Ransomware.csv | grep Address
```

Grep for Monero addresses by running

```
less Ransomware.csv | grep XMR
```

The same command can be used to search for other cryptocurrencies using the abbreviations in the list above.

<<<<<<< HEAD
### Chasingcoin.py
chasingcoin.py gathers basic information on amounts recieved in Bitcoin by accounts gathered, based on the output of coinlector.py.

```
python3 chasingcoin.py
```

The results are output to a filed called AccountsRecievingRansom.csv which displays the wallet address, number of transactions, total of Bitcoin received, total Bitcoin sent and the final wallet balance. View the results by running.

```
less AccountsRecievingRansom.csv
```

![Accounts Receiving Ransom CSV](/Assets/Images/accounts-receiving-ransom.png)

=======
>>>>>>> da53435e3fb2ca78950c692f73acd3773c0be2fc
### Tempuscoin.py
tempuscoin.py outputs a list of timestamped ransom transactions. The file TemporalRansoms.csv is created showing the sending and receiving Bitcoin addresses, the amount in BTC and its equivalent value in EUR, USD at the time of the transaction.

```
python3 tempuscoin.py
```

View the results by running.
```
less TemporalRansoms.csv
```

![Temporal Ransoms CSV](/Assets/Images/temporal-ransoms.png)

### Eventcoin.py

This code will probably need to be altered to be made usable with your own MISP instance. It uses PyMISP to create events from the Ransomware.csv file, and groups of events share the same name. The default is to create events that are not published, and then to add details by hand before publishing. YMMV.

## Consider Donating

We accept anonymous donations towards our software development on this project via a Monero address: 
82XYqsdEi6oCe2Rekg99pCjPxGCyJyNaA9m5R51LqDPgD1PGvS82YA9PUpPL3uXZf4ZZT2DnLBejKCXyk2YbmJUEB6FoTik

![A QR Code for donating to the software development](https://github.com/Concinnity-Risks/RansomCoinPublic/blob/master/RansomCoinMoneroDonationAddress.png)
