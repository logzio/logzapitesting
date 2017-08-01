import time
import os
import requests
import urllib2
import json


url='https://api.logz.io/v1/search'
headers = {
    X-USER-TOKEN': 'API-USER-KEY-HERE'
}
payload = {
  "size": 0,
  "query": {
    "bool": {
      "must": [{
        "range": {
          "@timestamp": {
            "gte": "now-5m",
            "lte": "now"
          }
        }
      }]
    }
  },
  "aggs": {
    "byType": {
      "terms": {
        "field": "type",
        "size": 5
      }
    }
  }
}
#print(payload)
r = requests.post(url, headers=headers, data=json.dumps(payload))
#print(r.status_code)
results=json.loads(r.text)
postdata = ''
for i in range(len(results['aggregations']['byType']['buckets'])):
#   print "{\"type\":\"" + results['aggregations']['byType']['buckets'][i]['key'] + "\",\"count\":"+ str(
#   results['aggregations']['byType']['buckets'][i]['doc_count']) + ",\"Severity\":3,\"Classification\":\"Potential DDos attack\",\"Query_Owner\":\"CGI\",\"Query_Verison\":\"v1\",\"key\":\"5002 DDoS Attack Detected: Scan or Flood\"}"
   postdata=postdata + "{\"type\":\"" + results['aggregations']['byType']['buckets'][i]['key'] + "\",\"count\":"+ str(
   results['aggregations']['byType']['buckets'][i]['doc_count']) + ",\"Severity\":3,\"Classification\":\"Potential DDos attack\",\"Query_Owner\":\"CGI\",\"Query_Verison\":\"v1\",\"key\":\"5002 DDoS Attack Detected: Scan or Flood\"}" + "\n"
print postdata
url2='http://listener.logz.io:8070'
payload={'token':'COLLECTOR-TOKEN-HERE'}
r2 = requests.post(url=url2,data=postdata,params=payload)
print(r2.status_code)
print(r.text)
