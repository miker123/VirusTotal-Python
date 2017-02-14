#!/usr/bin/env python
#Author: Mike R
#Date: 2/14/2017
#Purpose: Retrieve the VirusTotal results for a specifc hash. 

#In this instance, the user supplies the hash. This can be automated to accept from a csv or other format
#!/usr/bin/env python
import requests
import os

fileHash=raw_input("What is the md5/sha1/sha256 file hash to retrieve the VirusTotal Scan for:")
# To test, please use '7657fcb7d772448a6d8504e4b20168b8'

params = {'apikey': 'API-Key-Here', 'resource': fileHash}
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

file1='response.txt'
f=open(file1, 'w')
f.write(str(json_response))
f.close()

#get the values and format correctly
file1='response.txt'
f2=open(file1, 'r')
f3=open('response2.txt', 'w')
line=f2.read()
line2=line.replace('},', '\n\n')
line3=line2.replace('{', '\n')
line4=line3.replace('u\'', ' ')
line5=line4.replace('\':',':')
line6=line5.replace('\',',',')
line7=line6.replace('positives', '\npositives')
line8=line7.replace('\'','')

f3.write(line8)
f2.close()
f3.close()
