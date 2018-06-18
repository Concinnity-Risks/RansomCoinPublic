- linked_urls.json
	Contains all urls obtained so far in a dictionary structure. Each URL is a key, each top level value is a dictionary of Task ID/SHA256 hash pairs which that URL was detected in.
	This file was generated from a list of URLs in a file (locky_urls) using the script relate_urls.py

- locky_urls
	List of full URLs, one per line. Produced by retrieve_urls.py

- http.txt
	Raw logs for the Python server used to detect the HTTP requests.

- relate_urls.py
	Script to take URLs from file and compare these with json reports in the Cuckoo CWD to generate linked_urls.json

- retrieve_urls.py
	Script to extract Host and Path from the HTTP logs and form full URLs. Dumps to locky_urls

- http_server.py
	Repurposed HTTP server to handle requests on port 80 and issue responses (run with '-x' option to force 404 responses)
