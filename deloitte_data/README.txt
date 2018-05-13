This is some data that I got last year from a contact at Deloitte Argentinia.

Basically contains a bunch of sample hashes as well as lists of file
extensions based on Cuckoo reports. We can use this to identify new extensions
of interest.

Please don't share this data publicly.

You can extract all sample hashes (apparently just 1984) with jq(1) as
follows:

$ jq '.[][][]' -r input.json
...

$ jq '.[][][]' -r input.json|wc -l
1984
