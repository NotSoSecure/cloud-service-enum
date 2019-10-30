import requests
import pprint
from datetime import datetime
import json
import argparse
from argparse import RawTextHelpFormatter
from termcolor import colored
import sys
import os

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,description="""
< Azure_SERVICE_ENUM Says "Hello, world!" >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/
                ||----w |
                ||     ||

""")
optional = parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
required.add_argument("--access-token",  metavar='\b', required=True,help="Azure Managed Identities Access Token")
optional.add_argument('--logs',  action='store_true',help="Create a log File in same directory")
parser._action_groups.append(optional)
parser.parse_args(args=None if sys.argv[1:] else ['--help'])
args = parser.parse_args()

headers={"Authorization":"Bearer "+args.access_token}
#Start Time of Script
starttime=datetime.utcnow()

pprint.pprint("Start Time(UTC): " + str(starttime))
if args.logs == True:
    filename="logs-"+str(starttime.strftime('%d-%B-%Y-%H-%M-%S'))
    f=open(filename, 'w+')
#Add start time to log file
if args.logs == True:
    f.write("Start Time(UTC): " + str(starttime)+"\n")

response = requests.get("https://management.azure.com/subscriptions?api-version=2016-06-01",headers=headers)
for x in response.json()["value"]:
    subscriptionId=x["subscriptionId"]

response=requests.get("https://management.azure.com/subscriptions/"+subscriptionId+"/resources?api-version=2019-05-10",headers=headers)
#print response.json()["value"]

for y in response.json()["value"]:
    # Trying to get all supported API version by that service and then using same
    resourcevalue=y["id"]
    resourcevalue="https://management.azure.com"+resourcevalue+"?api-version=01-01-01"
    #print resourcevalue
    response=requests.get(resourcevalue,headers=headers)
    finalresponse=response.text
    teststring=finalresponse.split("The supported api-versions are '")[1]
    #print teststring
    apiversions=teststring.split("'. The supported locations are")[0]
    #print apiversions
    apiversionlist=apiversions.split(", ")
    #print apiversionlist
    for x in apiversionlist:
        if "preview" in x:
            apiversionlist.remove(x)
    #print apiversionlist
    #sortedlist=apiversionlist.sort(key = lambda date: datetime.strptime(date, '%Y-%b-%d')) 
    sortedlist=sorted(apiversionlist)
    #print sortedlist[-1]

    # Using above latest API version to fetch details
    resourcevalue=y["id"]
    resourcevalue="https://management.azure.com"+resourcevalue+"?api-version="+sortedlist[-1]
    #print resourcevalue
    if args.logs==True:
        f.write("Output of "+resourcevalue+"\n")
    print(colored("Output of "+resourcevalue+"\n",'green',attrs=['dark']))
    response=requests.get(resourcevalue,headers=headers)
    finalresponse=response.text
    pprint.pprint(finalresponse)
    if args.logs==True:
        f.write(finalresponse)

endtime=str(datetime.utcnow())
pprint.pprint("End Time(UTC): " + endtime)
if args.logs==True:
    f.write("End Time(UTC): " + endtime+"\n")
    f.close()
#End Time of script