#!/usr/bin/env python
#Author: Mike R
#Date: 2/6/2019
#Purpose: Retrieve the VirusTotal results for a specifc hash.

#In this instance, the user supplies the hash. This can be automated to accept from a csv or other format
#!/usr/bin/env python
import requests
import os

fileHash=raw_input("What is the md5/sha1/sha256 file hash to retrieve the VirusTotal Scan for:")
# To test, please use '7657fcb7d772448a6d8504e4b20168b8'
# Hash not there = 212ce8a9b6453a12206b4679cb947302
params = {'apikey': '', 'resource': fileHash}
headers = {
  "Accept-Encoding": "gzip, deflate",
  "User-Agent" : "gzip,  My Python requests library example client or username"
  }

#getting the reply
response = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
  params=params, headers=headers)
json_response = response.json()

#original JSON Response
#print json_response
#for key in json_response.keys():
#    print key

if json_response["response_code"] == 0:
    print "The file hasn't been scanned in VirusTotal. No results."
    
if json_response["response_code"] == 1:
    print "md5 hash: " + str(json_response["md5"])
    print "Scan Date: " + str(json_response["scan_date"])
    print "Positives: " + str(json_response["positives"])
    print "Total Results: " + str(json_response["total"]) 
