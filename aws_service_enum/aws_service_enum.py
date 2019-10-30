#!/usr/local/bin/python
# coding: utf-8
import boto3
from datetime import datetime
import argparse
import json
from argparse import RawTextHelpFormatter
from termcolor import colored
import sys
import pprint
import os

#List of AWS regions
regions=["us-east-1","us-east-2","us-west-1","us-west-2","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-west-3","eu-north-1","ap-northeast-1","ap-northeast-2","ap-northeast-3","ap-southeast-1","ap-southeast-2","ap-south-1","sa-east-1"]
#List of s3 bucket naming patters for different services
s3_enumeration_patterns=["elasticbeanstalk-REGIONNAME-ACCOUNTID","aws-athena-query-results-ACCOUNTID-REGIONNAME"]

parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter,description="""
< AWS_SERVICE_ENUM Says "Hello, world!" >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/
                ||----w |
                ||     ||

""")
optional = parser._action_groups.pop()
required = parser.add_argument_group('required arguments')
required.add_argument("--access-key",  metavar='\b', required=True,help="AWS Access Key ID")
required.add_argument("--secret-key",  metavar='\b', required=True,help="AWS Secret Key")
optional.add_argument("--session-token",  metavar='\b', help="AWS Security Token. Required if provided credentials do not have get-session-token access")
optional.add_argument("--region", metavar='\b', help='''\
Enter any value from given list 
ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-southeast-1, ap-southeast-2, ap-south-1
ca-central-1
eu-central-1, eu-west-1, eu-west-2, eu-west-3, eu-north-1
us-east-1, us-east-2, us-west-1, us-west-2
sa-east-1''')
optional.add_argument('--region-all', action='store_true', help="Enumerate for all regions given above")
optional.add_argument('--verbose', action='store_true', help="Select for Verbose output")
optional.add_argument('--s3-enumeration',  action='store_true',help="Enumerate possible S3 buckets associated with services like ElasticBeanstalk, Athena")
optional.add_argument('--logs',  action='store_true',help="Create a log File in same directory")
optional.add_argument("--command", help="Run commands directly. Make sure to install awscli(pip install awscli)")
parser._action_groups.append(optional)
parser.parse_args(args=None if sys.argv[1:] else ['--help'])
args = parser.parse_args()
# OS Shell to run command directly
if args.command:
    print(colored("Command Output: ",'blue',attrs=['dark']) + args.command)
    a=os.popen("aws configure set aws_access_key_id "+args.access_key)
    a=os.popen("aws configure set aws_secret_access_key "+args.secret_key)
    a=os.popen("aws configure set aws_session_token "+args.session_token)
    f = os.popen(args.command) 
    #pprint.pprint()"AWS_ACCESS_KEY="+args.access_key+" AWS_SECRET_KEY="+args.secret_key+" AWS_SESSION_TOKEN="+args.session_token+" "+args.command)
    #f = os.popen("sudo AWS_ACCESS_KEY="+args.access_key+" AWS_SECRET_KEY="+args.secret_key+" AWS_SESSION_TOKEN="+args.session_token+" "+args.command)
    for line in f.readlines(): 
        pprint.pprint(line)
    sys.exit()

#Start Time of Script
starttime=datetime.utcnow()

lines = []
with open("commands_list.txt") as file:
    for line in file: 
        line = line.strip() 
        if line!= "":
            if line[0]!="#":
                lines.append(line)

services=[]
#extracting all services from aws cli commands
for x in lines:
    y=x.split(" ")
    if y[1] not in services:
        if "-" not in y[1]:
            services.append(y[1])

if args.logs == True:
    filename="logs-"+str(starttime.strftime('%d-%B-%Y-%H-%M-%S'))
    f=open(filename, 'w+')


def enumeration(region,services):
    print(colored("Enumerating for region: "+region,'blue',attrs=['dark']))
    if args.logs==True:
        f.write("Enumerating for region: "+region+"\n")
    for service in services:
        service_name = "aws_"+service
        service_name= session.client(service)
        print(colored("Running checks for AWS "+ service,'blue',attrs=['dark']))
        if args.logs==True:
            f.write("Running checks for AWS "+ service+"\n")
        for x in lines:
            y=x.split(" ")
            # Executing all commands of particular service 
            if service == y[1]:     
                functionname=y[2].replace("-","_")
                try:
                    method_to_call = getattr(service_name,functionname)
                    response = method_to_call()
                    print(colored('Output of AWS '+y[1]+' -->'+y[2],'green',attrs=['dark']))
                    #pprint.pprint(response)
                    pprint.pprint(response)
                    if args.logs==True:
                        f.write("Output of AWS "+y[1]+" -->"+y[2]+"\n")
                        f.write(str(response)+"\n")
                except Exception as e:
                    #pprint.pprint(e) #only for debugging response
                    if args.verbose == True and "AccessDenied" in str(e):
                        print("AWS "+y[1]+" -->"+y[2]+": "+colored("Access Denied",'red',attrs=['dark']))
                        if args.logs==True:
                            f.write("AWS "+y[1]+" -->"+y[2]+": Access Denied\n")
                    elif "AuthorizationError" in str(e) and args.verbose == True:
                        print("AWS "+y[1]+" -->"+y[2]+": "+colored("Access Denied",'red',attrs=['dark']))
                        if args.logs==True:
                            f.write("AWS "+y[1]+" -->"+y[2]+": Access Denied\n")

    pprint.pprint("Total Number of services covered: "+str(len(services)))
    if args.logs==True:
        f.write("Total Number of services covered: "+str(len(services))+"\n")
    #s3 enumeration workflow start here
    if args.s3_enumeration == True:
        client = session.client('sts')
        response = client.get_caller_identity()
        #pprint.pprint(response)
        account_id=response["Account"]
        s3 = session.resource('s3')
        for services in s3_enumeration_patterns:
            for region in regions:
                words=services.split("-")
                words=[w.replace('ACCOUNTID', account_id) for w in words]
                words=[w.replace('REGIONNAME', region) for w in words]
                bucketname="-".join(words)
                #pprint.pprint(bucketname)
                my_bucket = s3.Bucket(bucketname)
                try:
                    response=my_bucket.objects.all()
                    if "NoSuchBucket" in response:
                        pass
                    else:
                        print(colored("aws s3 ls s3://"+bucketname, "green"))
                        if args.logs==True:
                            f.write("aws s3 ls s3://"+bucketname+"\n")
                    for obj in my_bucket.objects.all():
                        print(obj.key)
                        if args.logs==True:
                            f.write(obj.key)
                except Exception as e:
                    pass

if args.region in regions:
    if args.session_token:
        session = boto3.Session(aws_access_key_id=args.access_key,aws_secret_access_key=args.secret_key,aws_session_token=args.session_token, region_name=args.region)
        enumeration(args.region,services)
    else:
        session = boto3.Session(aws_access_key_id=args.access_key,aws_secret_access_key=args.secret_key, region_name=args.region)
        #generating temporary credentials(Valid for 1 hour)
        #client = session.client('sts')
        #credentials = client.get_session_token()
        #pprint.pprint(credentials["Credentials"]["AccessKeyId"])
        #session = boto3.Session(aws_access_key_id=credentials["Credentials"]["AccessKeyId"],aws_secret_access_key=credentials["Credentials"]["SecretAccessKey"], region_name=args.region)
        enumeration(args.region,services)
elif args.region_all:
    if args.session_token:
        for region in regions:
            session = boto3.Session(aws_access_key_id=args.access_key,aws_secret_access_key=args.secret_key,aws_session_token=args.session_token, region_name=region)
            enumeration(region,services)
    else:
        #generating temporary credentials(Valid for 1 hour)
        #client = session.client('sts')
        #credentials = client.get_session_token()
        #pprint.pprint(credentials)
        for region in regions:
            #session = boto3.Session(aws_access_key_id=credentials["Credentials"]["AccessKeyId"],aws_secret_access_key=credentials["Credentials"]["SecretAccessKey"], region_name=region)
            session = boto3.Session(aws_access_key_id=args.access_key,aws_secret_access_key=args.secret_key, region_name=region)
            enumeration(region,services)
else:
    if args.session_token:
        for region in regions:
            session = boto3.Session(aws_access_key_id=args.access_key,aws_secret_access_key=args.secret_key,aws_session_token=args.session_token, region_name=region)
            enumeration(region,services)
    else:
        session = boto3.Session(aws_access_key_id=args.access_key,aws_secret_access_key=args.secret_key, region_name=None)
        #generating temporary credentials(Valid for 1 hour)
        #client = session.client('sts')
        #credentials = client.get_session_token()
        #pprint.pprint(credentials)
        for region in regions:
            enumeration(region,services)


pprint.pprint("Start Time(UTC): " + str(starttime))
#Create a log file
if args.logs == True:
    f.write("Start Time(UTC): " + str(starttime)+"\n")

endtime=str(datetime.utcnow())
pprint.pprint("End Time(UTC): " + endtime)
if args.logs==True:
    f.write("End Time(UTC): " + endtime+"\n")
    f.close()
#End Time of script
