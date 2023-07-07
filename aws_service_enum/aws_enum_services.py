import boto3, argparse, threading, json
from tabulate import tabulate
from botocore.exceptions import ClientError
import crayons, warnings, concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
from prettytable import PrettyTable

warnings.filterwarnings("ignore", category=FutureWarning)

choices = ['ec2','s3','rds','lambda','cloudfront','dynamodb','iam','sns','sqs','ecr','elasticbeanstalk','route53','cloudwatch','codepipeline','sagemaker','secretsmanager','glue','stepfunctions','eks','cloudtrail','kinesis','redshift','elasticache',
'apigateway','cloudformation','appsync','ssm','elastictranscoder','datapipeline','mediaconvert','storagegateway','workspaces','cloud9','lex-models','iot','medialive','datasync','emr','athena','pinpoint','efs','mediapackage','mq','organizations','detective','opsworks','codecommit','appmesh','backup','mediapackage-vod','mediastore']

parser = argparse.ArgumentParser()
parser.add_argument('--access-key', help='Provide Access key', required=False)
parser.add_argument('--secret-key', help='Provide Secrect Key', required=False)
parser.add_argument('--session-token', help='Provide session token if available', required=False)
parser.add_argument('--list-services', help='Provide list of services', required=False,  action='store_true')
parser.add_argument('--services', help='Services that need to be enumerated', nargs='+', required=False, choices=choices)
parser.add_argument('--region', help='Provide regions, eg --region us-east-1, eu-north-1', required=False, nargs='+')
parser.add_argument('--thread', "-t", help='Treading count', required=False)
parser.add_argument('--output-file', "-o", help='json output in file', required=False)
args = parser.parse_args()


json_body = {}

if args.thread:
    Thread_Count = int(args.thread)
else:
    Thread_Count = 5

if args.list_services:
    services = [
    'ec2', 's3', 'rds', 'lambda', 'cloudfront', 'dynamodb', 'iam', 'sns', 'sqs', 'ecr',
    'elasticbeanstalk', 'route53', 'cloudwatch', 'codepipeline', 'sagemaker', 'secretsmanager',
    'glue', 'stepfunctions', 'eks', 'cloudtrail', 'kinesis', 'redshift', 'elasticache',
    'apigateway', 'cloudformation', 'appsync', 'ssm', 'elastictranscoder', 'datapipeline',
    'mediaconvert', 'storagegateway', 'workspaces', 'cloud9', 'lex-models', 'iot', 'medialive',
    'datasync', 'emr', 'athena', 'pinpoint', 'efs', 'mediapackage', 'mq', 'organizations',
    'detective', 'opsworks', 'codecommit', 'appmesh', 'backup', 'mediapackage-vod', 'mediastore'
    ]
    
    table = PrettyTable()
    table.field_names = ['Services']
    table.align['Services'] = 'l'  # Align the text to the left side

    for service in services:
        table.add_row([service])

    print(table)    
    exit()



access_key = args.access_key
secret_key = args.secret_key
session_token = args.session_token


if args.region == None:
    regions = ["eu-north-1","ap-south-1","eu-west-3","eu-west-2","eu-west-1","ap-northeast-3",
                    "ap-northeast-2","ap-northeast-1","sa-east-1","ca-central-1","ap-southeast-1",
                    "ap-southeast-2","eu-central-1","us-east-1","us-east-2","us-west-1","us-west-2"]
else:
    print(crayons.green("[+] Looking for specified region: ", bold=True), crayons.magenta(", ".join(args.region)))
    regions = args.region

def get_client(service_name, region_name=""):

    # config = Config(connect_timeout=20,
    #                 read_timeout=20,
    #                 retries={'max_attempts': 10},
    #                 max_pool_connections=MAX_POOL_CONNECTIONS * 2)

   
    client = boto3.client(
        service_name,
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region_name
    )
    
    return client

def describe_ec2_instances():
    started = "List EC2 instances:"
    instance_data = []

    def describe_instances(region):
        
        ec2_client = get_client('ec2', region_name=region)
        response = ec2_client.describe_instances()
  
        instances = response['Reservations']
        
        for reservation in instances:
            for instance in reservation['Instances']:
                instance_data.append([
                    instance['InstanceId'],
                    instance['State']['Name'],
                    instance['InstanceType'],
                    instance['LaunchTime'],
                    region
                ])
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_instances, region))
    
    json_body["ec2"] = instance_data

    if instance_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
  
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(instance_data, headers=['Instance ID', 'Instance State', 'Instance Type', 'Launch Time', 'Region'], tablefmt='psql'))

def describe_vpcs():
    started = "List VPCs:"
    vpc_data = []

    def describe_vpcs_in_region(region):
        ec2_client = get_client('ec2', region_name=region)
        response = ec2_client.describe_vpcs()
        vpcs = response['Vpcs']
        for vpc in vpcs:
            vpc_data.append([
                vpc['VpcId'],
                vpc['CidrBlock'],
                vpc['State'],
                region
            ])
   
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_vpcs_in_region, region))

    if vpc_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True))
    print(tabulate(vpc_data, headers=['VPC ID', 'CIDR Block', 'State', 'Region'], tablefmt='psql'))


def list_s3_buckets():
    started = "List S3 buckets:"
    s3_client = get_client('s3', region_name=None)
    response = s3_client.list_buckets()
    buckets = response['Buckets']
    bucket_data = []
    for bucket in buckets:
        bucket_data.append([
            bucket['Name'],
            bucket['CreationDate']            
        ])
    json_body["s3"] = bucket_data
    if bucket_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(bucket_data, headers=['Bucket Name', 'Creation Date'], tablefmt='psql'))

def describe_rds_instances():
    started = "List RDS instances:"
    instance_data = []

    def describe_instances(region):
        rds_client = get_client('rds', region_name=region)
        response = rds_client.describe_db_instances()
        instances = response['DBInstances']
        for instance in instances:
            instance_data.append([
                instance['DBInstanceIdentifier'],
                instance['DBInstanceClass'],
                instance['Engine'],
                instance['DBInstanceStatus'],
                region
            ])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_instances, region))

    json_body["rds"] = instance_data

    if not instance_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(instance_data, headers=['Instance Identifier', 'Instance Class', 'Engine', 'Instance Status', 'Region'], tablefmt='psql'))

def list_lambda_functions():
    started = "List Lambda functions:"
    function_data = []
    
    lambda_client = get_client('lambda',region_name=None)
    response = lambda_client.list_functions()   

    functions = response['Functions']
    
    for function in functions:
        function_data.append([
            function['FunctionName'],
            function['Runtime'],
            function['LastModified']
        ])

    json_body["lambda"] = function_data
    
    if function_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(function_data, headers=['Function Name', 'Runtime', 'Last Modified'], tablefmt='psql'))

def list_cloudfront_distributions():
    started = "List CloudFront distributions:"
    distribution_data = []

    def list_distributions(region):
        cloudfront_client = get_client('cloudfront', region_name=region)
        response = cloudfront_client.list_distributions()

        if "items" in response['DistributionList']:
            distributions = response['DistributionList']['Items']
            for distribution in distributions:
                distribution_data.append([
                    distribution['Id'],
                    distribution['ARN'],
                    distribution['Status'],
                    region
                ])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_distributions, region))

    json_body["cloudfront"] = distribution_data

    if not distribution_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(distribution_data, headers=['Distribution ID', 'ARN', 'Status', 'Region'], tablefmt='psql'))
    
def list_dynamodb_tables():
    started = "List DynamoDB tables:"
    table_data = []

    def list_tables(region):
        dynamodb_client = get_client('dynamodb', region_name=region)
        response = dynamodb_client.list_tables()

        tables = response['TableNames']
        for table in tables:
            table_data.append([table, region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_tables, region))
    json_body["dynamodb"] = table_data
    if not table_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(table_data, headers=['Table Name', 'Region'], tablefmt='psql'))


def list_iam_users():
    started = "List IAM users:"
    user_data = []
    iam_client = get_client('iam')
    response = iam_client.list_users()

    users = response['Users']
    
    for user in users:
        user_data.append([
            user['UserName'],
            user['UserId'],
            user['Arn']
        ])

    json_body["iam"] = user_data
    
    if user_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(user_data, headers=['Username', 'User ID', 'ARN', 'Region'], tablefmt='psql'))

def list_sns_topics():
    started = "List SNS topics:"
    topic_data = []

    def list_topics(region):
        sns_client = get_client('sns', region_name=region)
        response = sns_client.list_topics()

        topics = response['Topics']
        for topic in topics:
            topic_data.append([topic['TopicArn'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_topics, region))
    
    json_body["sns"] = topic_data

    if not topic_data:
        
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(topic_data, headers=['Topic ARN', 'Region'], tablefmt='psql'))
    

def list_sqs_queues():
    started = "List SQS queues:"
    queue_data = []

    def list_queues(region):
        sqs_client = get_client('sqs', region_name=region)
        response = sqs_client.list_queues()
        if "QueueUrls" in response:
            queues = response['QueueUrls']
            for queue in queues:
                queue_data.append([queue, region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_queues, region))

    json_body["sqs"] = queue_data

    if not queue_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(queue_data, headers=['Queue URL', 'Region'], tablefmt='psql'))


def describe_ecr_repositories():
    started = "List ECR repositories:"
    repository_data = []

    def describe_repositories(region):
        ecr_client = get_client('ecr', region_name=region)
        response = ecr_client.describe_repositories()

        repositories = response['repositories']
        for repository in repositories:
            repository_data.append([repository['repositoryName'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_repositories, region))
    json_body["ecr"] = repository_data
    if not repository_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(repository_data, headers=['Repository Name', 'Region'], tablefmt='psql'))

def describe_elasticbeanstalk_applications():
    started = "List Elastic Beanstalk applications:"
    application_data = []

    def describe_applications(region):
        elasticbeanstalk_client = get_client('elasticbeanstalk', region_name=region)
        response = elasticbeanstalk_client.describe_applications()
        applications = response['Applications']
        for application in applications:
            application_data.append([application['ApplicationName'], application['DateCreated'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_applications, region))
    json_body["elasticbeanstalk"] = application_data
    if not application_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(application_data, headers=['Application Name', 'Date Created', 'Region'], tablefmt='psql'))
    

def list_route53_hosted_zones():
    started = "List Route 53 hosted zones:"
    hosted_zone_data = []

    def list_hosted_zones(region):
        route53_client = get_client('route53', region_name=region)
        response = route53_client.list_hosted_zones()
        hosted_zones = response['HostedZones']
        for hosted_zone in hosted_zones:
            hosted_zone_data.append([hosted_zone['Name'], hosted_zone['Id'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_hosted_zones, region))

        for process in processes:
            process.result()
    json_body["route53"] = hosted_zone_data
    if not hosted_zone_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(hosted_zone_data, headers=['Hosted Zone Name', 'Hosted Zone ID', 'Region'], tablefmt='psql'))


def describe_cloudwatch_alarms():
    started = "List CloudWatch alarms:"
    alarm_data = []

    def describe_alarms(region):
        cloudwatch_client = get_client('cloudwatch', region_name=region)
        response = cloudwatch_client.describe_alarms()
        alarms = response['MetricAlarms']
        for alarm in alarms:
            alarm_data.append([alarm['AlarmName'], alarm['StateValue'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_alarms, region))

    json_body["cloudwatch"] = alarm_data

    if not alarm_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(alarm_data, headers=['Alarm Name', 'State Value', 'Region'], tablefmt='psql'))


def list_codepipeline_pipelines():
    started = "List CodePipeline pipelines:"
    pipeline_data = []

    def list_pipelines(region):
        codepipeline_client = get_client('codepipeline', region_name=region)
        if region == 'ap-northeast-3':
            return
        response = codepipeline_client.list_pipelines()
        pipelines = response['pipelines']
        for pipeline in pipelines:
            pipeline_data.append([pipeline['name'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=1) as executor:
        for region in regions:
            processes.append(executor.submit(list_pipelines, region))

        for process in as_completed(processes):
            process.result()
    json_body["codepipeline"] = pipeline_data
    if not pipeline_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(pipeline_data, headers=['Pipeline Name', 'Region'], tablefmt='psql'))


def list_sagemaker_notebooks():
    started = "List Sagemaker notebooks:"
    notebook_data = []

    def list_notebook_instances(region):
        sagemaker_client = get_client('sagemaker', region_name=region)
        response = sagemaker_client.list_notebook_instances()
        notebooks = response['NotebookInstances']
        for notebook in notebooks:
            notebook_data.append([notebook['NotebookInstanceName'], notebook['NotebookInstanceStatus'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_notebook_instances, region))
    json_body["sagemaker"] = notebook_data
    if not notebook_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(notebook_data, headers=['Notebook Instance Name', 'Notebook Instance Status', 'Region'],
                   tablefmt='psql'))
    

def list_secretsmanager_secrets():
    started = "List Secrets Manager secrets:"
    secret_data = []

    def list_secrets(region):
        secretsmanager_client = get_client('secretsmanager', region_name=region)
        response = secretsmanager_client.list_secrets()
        secrets = response['SecretList']
        for secret in secrets:
            secret_data.append([secret['Name'], secret['LastChangedDate'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_secrets, region))
    json_body["secretsmanager"] = secret_data
    if not secret_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(secret_data, headers=['Secret Name', 'Last Changed Date', 'Region'], tablefmt='psql'))


def list_glue_data_catalogs():
    started = "List Glue data catalogs:"
    catalog_data = []

    def list_catalogs(region):
        glue_client = get_client('glue', region_name=region)
        response = glue_client.get_databases()
        catalogs = response['DatabaseList']
        for catalog in catalogs:
            catalog_data.append([catalog['Name'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_catalogs, region))
    json_body["glue"] = catalog_data
    if not catalog_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(catalog_data, headers=['Data Catalog Name', 'Region'], tablefmt='psql'))


def list_stepfunctions_state_machines():
    started = "List Step Functions state machines:"
    state_machine_data = []

    def list_state_machines(region):
        stepfunctions_client = get_client('stepfunctions', region_name=region)
        response = stepfunctions_client.list_state_machines()
        state_machines = response['stateMachines']
        for state_machine in state_machines:
            state_machine_data.append([state_machine['name'], state_machine['status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_state_machines, region))
    json_body["stepfunctions"] = state_machine_data
    if not state_machine_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(state_machine_data, headers=['State Machine Name', 'Status', 'Region'], tablefmt='psql'))


def list_eks_clusters():
    started = "List EKS clusters:"
    cluster_data = []

    def list_clusters(region):
        eks_client = get_client('eks', region_name=region)
        response = eks_client.list_clusters()
        clusters = response['clusters']
        for cluster in clusters:
            cluster_data.append([cluster, region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_clusters, region))
    json_body["eks"] = cluster_data
    if not cluster_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(cluster_data, headers=['Cluster Name', 'Region'], tablefmt='psql'))

def describe_cloudtrail_trails():
    started = "List CloudTrail trails:"
    trail_data = []

    cloudtrail_client = get_client('cloudtrail', region_name=None)
    response = cloudtrail_client.describe_trails()
    trails = response['trailList']
    for trail in trails:
        trail_data.append([trail['Name'], trail['HomeRegion']])

    json_body["cloudtrail"] = trail_data
    if not trail_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(trail_data, headers=['Trail Name', 'Home Region'], tablefmt='psql'))

def list_kinesis_streams():
    started = "List Kinesis data streams:"
    stream_data = []

    def list_streams(region):
        kinesis_client = get_client('kinesis', region_name=region)
        response = kinesis_client.list_streams()
        streams = response['StreamNames']
        for stream in streams:
            stream_data.append([stream, region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_streams, region))
    
    json_body["kinesis"] = stream_data

    if not stream_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(stream_data, headers=['Stream Name', 'Region'], tablefmt='psql'))

def describe_redshift_clusters():
    started = "List Redshift clusters:"
    cluster_data = []

    def describe_clusters(region):
        redshift_client = get_client('redshift', region_name=region)
        response = redshift_client.describe_clusters()
        clusters = response['Clusters']
        for cluster in clusters:
            cluster_data.append([cluster['ClusterIdentifier'], cluster['NodeType'], cluster['ClusterStatus'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_clusters, region))
    json_body["redshift"] = cluster_data
    if not cluster_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(cluster_data, headers=['Cluster Identifier', 'Node Type', 'Cluster Status', 'Region'], tablefmt='psql'))

def describe_elasticache_clusters():
    started = "List Elasticache clusters:"
    cluster_data = []

    def describe_clusters(region):
        elasticache_client = get_client('elasticache', region_name=region)
        response = elasticache_client.describe_cache_clusters()
        clusters = response['CacheClusters']
        for cluster in clusters:
            cluster_data.append([cluster['CacheClusterId'], cluster['Engine'], cluster['CacheClusterStatus'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_clusters, region))

    json_body["elasticache"] = cluster_data

    if not cluster_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(cluster_data, headers=['Cache Cluster ID', 'Engine', 'Cluster Status', 'Region'], tablefmt='psql'))

def list_apigateway_apis():
    started = "List API Gateway APIs:"
    api_data = []

    def get_rest_apis(region):
        apigateway_client = get_client('apigateway', region_name=region)
        response = apigateway_client.get_rest_apis()
        apis = response['items']
        for api in apis:
            api_data.append([api['name'], api['description'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(get_rest_apis, region))

    json_body["apigateway"] = api_data

    if not api_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(api_data, headers=['API Name', 'Description', 'Region'], tablefmt='psql'))


def list_cloudformation_stacks():
    started = "List CloudFormation stacks:"
    stack_data = []

    def get_stacks(region):
        cloudformation_client = get_client('cloudformation', region_name=region)
        response = cloudformation_client.list_stacks()
        stacks = response['StackSummaries']
        for stack in stacks:
            stack_data.append([stack['StackName'], stack['StackStatus'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(get_stacks, region))

    json_body["cloudformation"] = stack_data
    
    if stack_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(stack_data, headers=['Stack Name', 'Stack Status', 'Region'], tablefmt='psql'))

def list_appsync_apis():
    started = "List AppSync APIs:"
    api_data = []

    def get_apis(region):
        appsync_client = get_client('appsync', region_name=region)
        response = appsync_client.list_graphql_apis()
        apis = response['graphqlApis']
        for api in apis:
            api_data.append([api['name'], api['authenticationType'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(get_apis, region))

    json_body["appsync"] = api_data

    if not api_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(api_data, headers=['API Name', 'Authentication Type', 'Region'], tablefmt='psql'))

def list_ssm_documents():
    started = "List Systems Manager documents:"
    document_data = []

   
    ssm_client = get_client('ssm', region_name=None)
    response = ssm_client.list_documents()
    documents = response['DocumentIdentifiers']
    for document in documents:
        document_data.append([document['Name'], document['DocumentType']])

    json_body["ssm"] = document_data

    if not document_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(document_data, headers=['Document Name', 'Document Type'], tablefmt='psql'))

def list_elastictranscoder_pipelines():
    started = "List Elastic Transcoder pipelines:"
    pipeline_data = []

    def get_pipelines(region):
        elastictranscoder_client = get_client('elastictranscoder', region_name=region)
        response = elastictranscoder_client.list_pipelines()
        pipelines = response['Pipelines']
        for pipeline in pipelines:
            pipeline_data.append([pipeline['Name'], pipeline['Status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(get_pipelines, region))

    json_body["elastictranscoder"] = pipeline_data

    if not pipeline_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(pipeline_data, headers=['Pipeline Name', 'Status', 'Region'], tablefmt='psql'))

def list_datapipeline_pipelines():
    started = "List Data Pipeline pipelines:"
    pipeline_data = []

    def get_pipelines(region):
        datapipeline_client = get_client('datapipeline', region_name=region)
        response = datapipeline_client.list_pipelines()
        pipelines = response['pipelineIdList']
        for pipeline in pipelines:
            pipeline_data.append([pipeline['name'], pipeline['status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(get_pipelines, region))

    json_body["datapipeline"] = pipeline_data

    if not pipeline_data:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n",
          tabulate(pipeline_data, headers=['Pipeline Name', 'Status', 'Region'], tablefmt='psql'))

def list_mediaconvert_jobs():
    started = "List MediaConvert jobs:"
    
    try:
        job_data = []
        for region in regions:
            if region == "ap-northeast-3":
                continue
            mediaconvert_client = get_client('mediaconvert', region_name=region)
            response = mediaconvert_client.list_jobs()

            jobs = response['Jobs']
            
            for job in jobs:
                job_data.append([job['Id'], job['Status'],region])
        
        json_body["mediaconvert"] = job_data
        
        if job_data == []:
            print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
            return
        
        print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(job_data, headers=['Job ID', 'Status', 'Region'], tablefmt='psql'))
    except ClientError as e:
        error_code = e.response['Error']['Code']
        if error_code == 'ForbiddenException':
            print(crayons.red("Error: You must use the subscription API to subscribe your account to the service before using this operation.", bold=True))
        else:
            print(crayons.red("An error occurred: "+ str(e), bold=True))

def list_storagegateway_gateways():
    started = "List Storage Gateway gateways:"
    gateway_data = []

    def list_gateways(region):
        storagegateway_client = get_client('storagegateway', region_name=region)
        response = storagegateway_client.list_gateways()
        gateways = response['Gateways']
        for gateway in gateways:
            gateway_data.append([gateway['GatewayId'], gateway['GatewayType'], gateway['GatewayOperationalState'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_gateways, region))
    json_body["storagegateway"] = gateway_data
    if gateway_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(gateway_data, headers=['Gateway ID', 'Gateway Type', 'Operational State', 'Region'], tablefmt='psql'))


def describe_workspaces():
    started = "List WorkSpaces:"
    workspace_data = []

    def describe_workspaces_in_region(region):
        workspaces_client = get_client('workspaces', region_name=region)
        response = workspaces_client.describe_workspaces()
        workspaces = response['Workspaces']
        for workspace in workspaces:
            workspace_data.append([workspace['WorkspaceId'], workspace['UserName'], workspace['State'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_workspaces_in_region, region))

    json_body["workspaces"] = workspace_data

    if workspace_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(workspace_data, headers=['Workspace ID', 'User Name', 'State', 'Region'], tablefmt='psql'))


def list_cloud9_environments():
    started = "List Cloud9 environments:"
    environment_data = []

    def list_environments_in_region(region):
        cloud9_client = get_client('cloud9', region_name=region)
        response = cloud9_client.list_environments()
        environments = response['environmentIds']
        for environment in environments:
            environment_data.append([environment, region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_environments_in_region, region))

    json_body["cloud9"] = environment_data

    if environment_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(environment_data, headers=['Environment ID', 'Region'], tablefmt='psql'))

def list_lex_bots():
    started = "List Lex bots:"
    bot_data = []

    def list_bots_in_region(region):
        lex_client = get_client('lex-models', region_name=region)
        response = lex_client.get_bots()
        bots = response['bots']
        for bot in bots:
            bot_data.append([bot['name'], bot['status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_bots_in_region, region))

    json_body["lex"] = bot_data

    if bot_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(bot_data, headers=['Bot Name', 'Status', 'Region'], tablefmt='psql'))

def list_iot_things():
    started = "List IoT things:"
    thing_data = []

    def list_things_in_region(region):
        iot_client = get_client('iot', region_name=region)
        response = iot_client.list_things()
        things = response['things']
        for thing in things:
            thing_data.append([thing['thingName'], thing['thingTypeName'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_things_in_region, region))

    json_body["iot"] = thing_data

    if thing_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(thing_data, headers=['Thing Name', 'Thing Type', 'Region'], tablefmt='psql'))

def list_medialive_channels():
    started = "List MediaLive channels:"
    channel_data = []
    
    def list_channels_in_region(region):
        medialive_client = get_client('medialive', region_name=region)
        response = medialive_client.list_channels()
        channels = response['Channels']
        
        for channel in channels:
            channel_data.append([channel['ChannelName'], channel['State'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_channels_in_region, region))

    json_body["medialive"] = channel_data

    if channel_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(channel_data, headers=['Channel Name', 'State', 'Region'], tablefmt='psql'))

def list_datasync_tasks():
    started = "List DataSync tasks:"
    task_data = []
    
    def list_tasks_in_region(region):
        datasync_client = get_client('datasync', region_name=region)
        response = datasync_client.list_tasks()
        tasks = response['Tasks']
        
        for task in tasks:
            task_data.append([task['TaskArn'], task['Status'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_tasks_in_region, region))

    json_body["datasync"] = task_data
        
    if task_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(task_data, headers=['Task ARN', 'Status', 'Region'], tablefmt='psql'))

def list_emr_clusters():
    started = "List Elastic MapReduce (EMR) clusters:"
    cluster_data = []
    
    def list_clusters_in_region(region):
        emr_client = get_client('emr', region_name=region)
        response = emr_client.list_clusters()
        clusters = response['Clusters']
        
        for cluster in clusters:
            cluster_data.append([cluster['Id'], cluster['Name'], cluster['Status']['State'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_clusters_in_region, region))

    json_body["emr"] = cluster_data

    if cluster_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(cluster_data, headers=['Cluster ID', 'Name', 'Status', 'Region'], tablefmt='psql'))

def list_athena_workgroups():
    started = "List Athena workgroups:"
    workgroup_data = []
    
    def list_workgroups_in_region(region):
        athena_client = get_client('athena', region_name=region)
        response = athena_client.list_work_groups()
        workgroups = response['WorkGroups']
        
        for workgroup in workgroups:
            workgroup_data.append([workgroup['Name'], workgroup['State'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_workgroups_in_region, region))

    json_body["athena"] = workgroup_data

    if workgroup_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(workgroup_data, headers=['WorkGroup Name', 'State', 'Region'], tablefmt='psql'))
    
def list_pinpoint_applications():
    started = "List Pinpoint applications:"
    application_data = []
    
    def list_applications_in_region(region):
        pinpoint_client = get_client('pinpoint', region_name=region)
        response = pinpoint_client.get_apps()
        applications = response['ApplicationsResponse']["Item"]
        
        for application in applications:
            application_data.append([application['Id'], application['Name'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(list_applications_in_region, region))

    json_body["pinpoint"] = application_data

    if application_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(application_data, headers=['Application ID', 'Name', 'Region'], tablefmt='psql'))

def list_efs_file_systems():
    started = "List Elastic File System (EFS) file systems:"
    file_system_data = []
    
    def describe_file_systems_in_region(region):
        efs_client = get_client('efs', region_name=region)
        response = efs_client.describe_file_systems()
        file_systems = response['FileSystems']
        
        for fs in file_systems:
            file_system_data.append([fs['FileSystemId'], fs['CreationTime'], fs['SizeInBytes']['Value'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_file_systems_in_region, region))
    
    json_body["efs"] = file_system_data

    if file_system_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(file_system_data, headers=['File System ID', 'Creation Time', 'Size (Bytes)', 'Region'], tablefmt='psql'))

def list_glue_crawlers():
    started = "List Glue crawlers:"
    crawler_data = []
    
    def describe_crawlers_in_region(region):
        glue_client = get_client('glue', region_name=region)
        response = glue_client.get_crawlers()
        crawlers = response['Crawlers']
        
        for crawler in crawlers:
            crawler_data.append([crawler['Name'], crawler['State'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_crawlers_in_region, region))

    json_body["glue"] = crawler_data

    if crawler_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(crawler_data, headers=['Crawler Name', 'State', 'Region'], tablefmt='psql'))


def list_datasync_locations():
    started = "List DataSync locations:"
    location_data = []
    
    def describe_locations_in_region(region):
        datasync_client = get_client('datasync', region_name=region)
        response = datasync_client.list_locations()
        locations = response['Locations']
        
        for location in locations:
            location_data.append([location['LocationArn'], location['LocationUri'], location['LocationType'], region])
    
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_locations_in_region, region))

    json_body["datasync"] = location_data

    if location_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(location_data, headers=['Location ARN', 'Location URI', 'Location Type', 'Region'], tablefmt='psql'))

def list_mediapackage_channels():
    started = "List MediaPackage channels:"
    channel_data = []
    for region in regions:
        try:
            mediapackage_client = get_client('mediapackage', region_name=region)
            response = mediapackage_client.list_channels()
        except:
            continue
        channels = response['Channels']
        
        for channel in channels:
            channel_data.append([channel['Id'], channel['Description'], channel['Status'],region])
    
    json_body["mediapackage"] = channel_data

    if channel_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(channel_data, headers=['Channel ID', 'Description', 'Status', 'Region'], tablefmt='psql'))

def list_mq_brokers():
    started = "List MQ brokers (Amazon MQ):"
    broker_data = []
    for region in regions:
        mq_client = get_client('mq', region_name=region)
        response = mq_client.list_brokers()

        brokers = response['BrokerSummaries']
        
        for broker in brokers:
            broker_data.append([broker['BrokerId'], broker['BrokerName'], broker['BrokerState'],region])
    
    json_body["mq"] = broker_data

    if broker_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(broker_data, headers=['Broker ID', 'Broker Name', 'Broker State', 'Region'], tablefmt='psql'))

def list_organizations_accounts():
    started = "List Organizations:"
    account_data = []

    def process_region(region):
        organizations_client = get_client('organizations', region_name=region)
        response = organizations_client.list_accounts()
        accounts = response['Accounts']
        for account in accounts:
            account_data.append([account['Id'], account['Name'], account['Status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))

    json_body["organizations"] = account_data

    if account_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(account_data, headers=['Account ID', 'Account Name', 'Status', 'Region'], tablefmt='psql'))

def list_detective_graphs():
    started = "List Detective graphs:"
    graph_data = []

    def process_region(region):
        detective_client = get_client('detective', region_name=region)
        response = detective_client.list_graphs()
        graphs = response['GraphList']
        for graph in graphs:
            graph_data.append([graph['Arn'], graph['CreatedTime'], graph['Status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))

    json_body["detective"] = graph_data

    if graph_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(graph_data, headers=['Graph ARN', 'Created Time', 'Status', 'Region'], tablefmt='psql'))


def list_opsworks_stacks():
    started = "List OpsWorks stacks:"
    stack_data = []

    def process_region(region):
        opsworks_client = get_client('opsworks', region_name=region)
        response = opsworks_client.describe_stacks()
        stacks = response['Stacks']
        for stack in stacks:
            stack_data.append([stack['StackId'], stack['Name'], stack['Status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))

    json_body["opsworks"] = stack_data

    if stack_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(stack_data, headers=['Stack ID', 'Name', 'Status', 'Region'], tablefmt='psql'))

def list_codecommit_repositories():
    started = "List CodeCommit repositories:"
    repository_data = []

    def process_region(region):
        codecommit_client = get_client('codecommit', region_name=region)
        response = codecommit_client.list_repositories()
        repositories = response['repositories']
        for repository in repositories:
            repository_data.append([repository['repositoryId'], repository['repositoryName'], repository['repositoryDescription'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))
    json_body["codecommit"] = repository_data
    if repository_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(repository_data, headers=['Repository ID', 'Name', 'Description', 'Region'], tablefmt='psql'))

def list_cloudformation_change_sets():
    started = "List CloudFormation change sets:"
    def list_change_sets(stack_name, region):
        cloudformation_client = get_client('cloudformation', region_name=region)
        try:
            response = cloudformation_client.list_change_sets(StackName=stack_name)
        except ClientError as e:
            #print(e)
            error_message = e.response['Error']['Message']
            #print(crayons.red(f"Error retrieving change sets: {error_message} ({region})", bold=True))
            return
            

        change_sets = response['Summaries']
        change_set_data = []
        for change_set in change_sets:
            change_set_data.append([change_set['ChangeSetName'], change_set['StackName'], change_set['Status'],region])

        json_body["cloudformation"].append(change_set_data)

        if change_set_data == []:
            print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
            return

        print(crayons.green("[+] " + started, bold=True), "\r\n" ,tabulate(change_set_data, headers=['Change Set Name', 'Stack Name', 'Status', 'Region'], tablefmt='psql'))
    json_body["cloudformation"] = []
    for region in regions:
        cloudformation_client = get_client('cloudformation', region_name=region)
        response = cloudformation_client.list_stacks()

        stacks = response['StackSummaries']
        stack_names = [stack['StackName'] for stack in stacks]
        
        threads = []
        for stack_name in stack_names:
            t = threading.Thread(target=list_change_sets, args=(stack_name, region))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

def list_appmesh_meshes():
    started = "List App Mesh meshes:"
    mesh_data = []

    def process_region(region):
        appmesh_client = get_client('appmesh', region_name=region)
        response = appmesh_client.list_meshes()
        meshes = response['meshes']
        for mesh in meshes:
            mesh_data.append([mesh['MeshName'], mesh['CreatedTime'], mesh['Status'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))

    json_body["appmesh"] = mesh_data

    if mesh_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(mesh_data, headers=['Mesh Name', 'Created Time', 'Status', 'Region'], tablefmt='psql'))


def list_backup_plans():
    started = "List AWS Backup plans:"
    plan_data = []

    def process_region(region):
        backup_client = get_client('backup', region_name=region)
        response = backup_client.list_backup_plans()
        plans = response['BackupPlansList']
        for plan in plans:
            plan_data.append([plan['BackupPlanId'], plan['BackupPlanName'], plan['CreationDate'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))

    json_body["backup"] = plan_data

    if plan_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(plan_data, headers=['Plan ID', 'Plan Name', 'Creation Date', 'Region'], tablefmt='psql'))

def list_mediapackage_vod_assets():
    started = "List MediaPackage VOD assets:"
    asset_data = []

    def process_region(region):
        mediapackage_vod_client = get_client('mediapackage-vod', region_name=region)
        response = mediapackage_vod_client.list_assets()
        assets = response['Assets']
        for asset in assets:
            asset_data.append([asset['Id'], asset['Arn'], asset['CreatedAt'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))

    json_body["mediapackage-vod"] = asset_data

    if asset_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(asset_data, headers=['Asset ID', 'ARN', 'Created At', 'Region'], tablefmt='psql'))

def list_mediastore_containers():
    started = "List Elemental MediaStore containers:"
    container_data = []

    def process_region(region):
        mediastore_client = get_client('mediastore', region_name=region)
        response = mediastore_client.list_containers()
        containers = response['Containers']
        for container in containers:
            container_data.append([container['Name'], container['Status'], container['CreationTime'], region])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(process_region, region))
    json_body["mediastore"] = container_data
    if container_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return
    print(crayons.green("[+] " + started, bold=True), "\r\n", tabulate(container_data, headers=['Container Name', 'Status', 'Creation Time', 'Region'], tablefmt='psql'))

def describe_snapshots():
    started = "List EBS Snapshots:"
    snapshot_data = []

    def describe_snapshots_in_region(region):
        ec2_client = get_client('ec2', region_name=region)
        response = ec2_client.describe_snapshots(OwnerIds=['self'])
        snapshots = response['Snapshots']

        for snapshot in snapshots:
            snapshot_data.append([
                snapshot['SnapshotId'],
                snapshot['VolumeId'],
                snapshot['StartTime'],
                snapshot['State'],
                region
            ])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_snapshots_in_region, region))

    if snapshot_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    print(crayons.green("[+] " + started, bold=True))
    print(tabulate(snapshot_data, headers=['Snapshot ID', 'Volume ID', 'Start Time', 'State', 'Region'], tablefmt='psql'))


def describe_subnets():
    started = "List Subnets:"
    subnet_data = []

    def describe_subnets_in_region(region):
        ec2_client = get_client('ec2', region_name=region)
        response = ec2_client.describe_subnets()
        subnets = response['Subnets']

        for subnet in subnets:
            subnet_data.append([
                subnet['SubnetId'],
                subnet['VpcId'],
                subnet['CidrBlock'],
                subnet['AvailabilityZone'],
                region
            ])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_subnets_in_region, region))

    if subnet_data == []:
        print(crayons.yelow("[!] " + started + " (Empty!)", bold=True))
        return

    headers = ['Subnet ID', 'VPC ID', 'CIDR Block', 'Availability Zone', 'Region']
    print(crayons.green("[+] " + started, bold=True))
    print(tabulate(subnet_data, headers=headers, tablefmt='psql'))


def describe_volumes():
    started = "List EBS Volumes:"
    volume_data = []

    def describe_volumes_in_region(region):
        ec2_client = boto3.client('ec2', region_name=region)
        response = ec2_client.describe_volumes()
        volumes = response['Volumes']

        for volume in volumes:
            volume_data.append([
                volume['VolumeId'],
                volume['Size'],
                volume['AvailabilityZone'],
                volume['State'],
                region
            ])
    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_volumes_in_region, region))

    if volume_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    headers = ['Volume ID', 'Size (GiB)', 'Availability Zone', 'State', 'Region']
    print(crayons.green("[+] " + started, bold=True))
    print(tabulate(volume_data, headers=headers, tablefmt='psql'))

def describe_amis():
    started = "List AMIs:"
    ami_data = []

    def describe_amis_in_region(region):
       
        ec2_client = get_client('ec2', region_name=region)
        response = ec2_client.describe_images(Owners=['self'])
        amis = response['Images']

        for ami in amis:
            ami_data.append([
                ami['ImageId'],
                ami['Name'],
                ami['CreationDate'],
                region
            ])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_amis_in_region, region))

    if ami_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    headers = ['AMI ID', 'Name', 'Creation Date', 'Region']
    print(crayons.green("[+] " + started, bold=True))
    print(tabulate(ami_data, headers=headers, tablefmt='psql'))

def describe_security_groups():
    started = "List Security Groups:"
    group_data = []

    def describe_security_groups_in_region(region):
        ec2_client = get_client('ec2', region_name=region)
        response = ec2_client.describe_security_groups()
        security_groups = response['SecurityGroups']

        for group in security_groups:
            group_data.append([
                group['GroupId'],
                group['GroupName'],
                group['Description'],
                region
            ])

    processes = []
    with ThreadPoolExecutor(max_workers=Thread_Count) as executor:
        for region in regions:
            processes.append(executor.submit(describe_security_groups_in_region, region))

    if group_data == []:
        print(crayons.yellow("[!] " + started + " (Empty!)", bold=True))
        return

    headers = ['Group ID', 'Group Name', 'Description', 'Region']
    print(crayons.green("[+] " + started, bold=True))
    print(tabulate(group_data, headers=headers, tablefmt='psql'))


services_list = {
  "ec2": "describe_ec2_instances","vpc":"describe_vpcs","s3": "list_s3_buckets","rds": "describe_rds_instances","lambda": "list_lambda_functions","cloudfront": "list_cloudfront_distributions","dynamodb": "list_dynamodb_tables","iam": "list_iam_users","sns": "list_sns_topics",
  "sqs": "list_sqs_queues","ecr": "describe_ecr_repositories","elasticbeanstalk": "describe_elasticbeanstalk_applications","route53": "list_route53_hosted_zones","cloudwatch": "describe_cloudwatch_alarms","codepipeline": "list_codepipeline_pipelines","sagemaker": "list_sagemaker_notebooks",
  "secretsmanager": "list_secretsmanager_secrets","glue": "list_glue_data_catalogs","stepfunctions": "list_stepfunctions_state_machines","eks": "list_eks_clusters","cloudtrail": "describe_cloudtrail_trails","kinesis": "list_kinesis_streams","redshift": "describe_redshift_clusters",
  "elasticache": "describe_elasticache_clusters","apigateway": "list_apigateway_apis","cloudformation": "list_cloudformation_stacks","appsync": "list_appsync_apis","ssm": "list_ssm_documents","elastictranscoder": "list_elastictranscoder_pipelines","datapipeline": "list_datapipeline_pipelines",
  "mediaconvert": "list_mediaconvert_jobs","storagegateway": "list_storagegateway_gateways","workspaces": "describe_workspaces","cloud9": "list_cloud9_environments","lex-models": "list_lex_bots","iot": "list_iot_things","medialive": "list_medialive_channels","datasync": "list_datasync_tasks",
  "emr": "list_emr_clusters","athena": "list_athena_workgroups","pinpoint": "list_pinpoint_applications","efs": "list_efs_file_systems","mediapackage": "list_mediapackage_channels","mq": "list_mq_brokers","organizations": "list_organizations_accounts","detective": "list_detective_graphs",
  "opsworks": "list_opsworks_stacks","codecommit": "list_codecommit_repositories","appmesh": "list_appmesh_meshes","backup": "list_backup_plans","mediapackage-vod": "list_mediapackage_vod_assets","mediastore": "list_mediastore_containers","Snapshots":"describe_snapshots","Subnet":"describe_subnets",
  "Volumes":"describe_volumes","ami":"describe_amis","SecurityGroups":"describe_security_groups"
}


functions = [
    describe_ec2_instances,describe_vpcs,list_s3_buckets,describe_rds_instances,list_lambda_functions,list_cloudfront_distributions,list_dynamodb_tables,list_iam_users,list_sns_topics,list_sqs_queues,describe_ecr_repositories,describe_elasticbeanstalk_applications,list_route53_hosted_zones,
    describe_cloudwatch_alarms,list_codepipeline_pipelines,list_sagemaker_notebooks,list_secretsmanager_secrets,list_glue_data_catalogs,list_stepfunctions_state_machines,list_eks_clusters,describe_cloudtrail_trails,list_kinesis_streams,describe_redshift_clusters,
    describe_elasticache_clusters,list_apigateway_apis,list_cloudformation_stacks,list_appsync_apis,list_ssm_documents,list_elastictranscoder_pipelines,list_datapipeline_pipelines,list_mediaconvert_jobs,list_storagegateway_gateways,describe_workspaces,list_cloud9_environments,
    list_lex_bots,list_iot_things,list_medialive_channels,list_datasync_tasks,list_emr_clusters,list_athena_workgroups,list_pinpoint_applications,list_efs_file_systems,list_glue_crawlers,list_datasync_locations,list_mediapackage_channels,list_mq_brokers,list_organizations_accounts,
    list_detective_graphs,list_opsworks_stacks,list_codecommit_repositories,list_cloudformation_change_sets,list_appmesh_meshes,list_backup_plans,list_mediapackage_vod_assets,list_mediastore_containers,describe_snapshots,
    describe_subnets,describe_volumes,describe_amis,describe_security_groups
]



def get_profile():
    profile = get_client("sts", region_name=None)
    try:
        response = profile.get_caller_identity()
        userId = response["UserId"]
        account = response["Account"]
        arn = response["Arn"]
        print()
        print(crayons.magenta("[+] User Profile", bold=True))
        print(crayons.yellow("UserId: " + userId, bold=True))
        print(crayons.yellow("Account: " + account, bold=True))
        print(crayons.yellow("Arn: " + arn, bold=True))
        print("-------------------------------------------")
        print()
    except:
        print(crayons.red("[!] Access tokens is not valid!"))
        exit()

if args.access_key and args.secret_key:
    get_profile()
    # Define the number of threads to run concurrently
    num_threads = 5

    if args.services != None:
        specific_args = []
        for srv in args.services:
            specific_args.append(services_list[srv])
        # Filter the functions based on the specified services
        filtered_functions = [func for func in functions if func.__name__ in specific_args]
    else:
        # Execute all functions
        filtered_functions = functions

    with concurrent.futures.ThreadPoolExecutor() as executor:
        # Submit the filtered functions to the executor
        futures = [executor.submit(f) for f in filtered_functions]

        # Wait for the first num_threads futures to complete
        for future in concurrent.futures.as_completed(futures[:num_threads]):
            pass

else:
    print(crayons.red("[-] Please provide --access-key and --secret-key!", bold=True))


if args.output_file:

    with open(args.output_file, 'w') as file:
        json.dump(json_body, file, indent=4, sort_keys=True, default=str)
    print()
    print(crayons.green(f'AWS data saved to {args.output_file}', bold=True))
    print()
