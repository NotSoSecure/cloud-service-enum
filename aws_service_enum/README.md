This tool is helpful in scenarios where you got AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) through SSRF or any other vulnerability, but you are not sure if given credentials have access to other services or not. Instead of just trying for top 10 aws services (s3, ec2, etc), you can run this tool and it will let you enumerate through each non-intrusive(For example, only listing buckets, this tool won't be creating/modifying bucket) feature of each service. 

## Requirements

* `pip install -r requirements.txt`

## Usage

~~~
usage: aws_enum_services.py [-h] [--access-key ACCESS_KEY] [--secret-key SECRET_KEY] [--session-token SESSION_TOKEN]
                            [--list-services]
                            [--services {ec2,s3,rds,lambda,cloudfront,dynamodb,iam,sns,sqs,ecr,elasticbeanstalk,route53,cloudwatch,codepipeline,sagemaker,secretsmanager,glue,stepfunctions,eks,cloudtrail,kinesis,redshift,elasticache,apigateway,cloudformation,appsync,ssm,elastictranscoder,datapipeline,mediaconvert,storagegateway,workspaces,cloud9,lex-models,iot,medialive,datasync,emr,athena,pinpoint,efs,mediapackage,mq,organizations,detective,opsworks,codecommit,appmesh,backup,mediapackage-vod,mediastore} [{ec2,s3,rds,lambda,cloudfront,dynamodb,iam,sns,sqs,ecr,elasticbeanstalk,route53,cloudwatch,codepipeline,sagemaker,secretsmanager,glue,stepfunctions,eks,cloudtrail,kinesis,redshift,elasticache,apigateway,cloudformation,appsync,ssm,elastictranscoder,datapipeline,mediaconvert,storagegateway,workspaces,cloud9,lex-models,iot,medialive,datasync,emr,athena,pinpoint,efs,mediapackage,mq,organizations,detective,opsworks,codecommit,appmesh,backup,mediapackage-vod,mediastore} ...]]
                            [--region REGION [REGION ...]] [--thread THREAD] [--output-file OUTPUT_FILE]

options:
  -h, --help            show this help message and exit
  --access-key ACCESS_KEY
                        Provide Access key
  --secret-key SECRET_KEY
                        Provide Secrect Key
  --session-token SESSION_TOKEN
                        Provide session token if available
  --list-services       Provide list of services
  --services {ec2,s3,rds,lambda,cloudfront,dynamodb,iam,sns,sqs,ecr,elasticbeanstalk,route53,cloudwatch,codepipeline,sagemaker,secretsmanager,glue,stepfunctions,eks,cloudtrail,kinesis,redshift,elasticache,apigateway,cloudformation,appsync,ssm,elastictranscoder,datapipeline,mediaconvert,storagegateway,workspaces,cloud9,lex-models,iot,medialive,datasync,emr,athena,pinpoint,efs,mediapackage,mq,organizations,detective,opsworks,codecommit,appmesh,backup,mediapackage-vod,mediastore} [{ec2,s3,rds,lambda,cloudfront,dynamodb,iam,sns,sqs,ecr,elasticbeanstalk,route53,cloudwatch,codepipeline,sagemaker,secretsmanager,glue,stepfunctions,eks,cloudtrail,kinesis,redshift,elasticache,apigateway,cloudformation,appsync,ssm,elastictranscoder,datapipeline,mediaconvert,storagegateway,workspaces,cloud9,lex-models,iot,medialive,datasync,emr,athena,pinpoint,efs,mediapackage,mq,organizations,detective,opsworks,codecommit,appmesh,backup,mediapackage-vod,mediastore} ...]
                        Services that need to be enumerated
  --region REGION [REGION ...]
                        Provide regions, eg --region us-east-1, eu-north-1
  --thread THREAD, -t THREAD
                        Treading count
  --output-file OUTPUT_FILE, -o OUTPUT_FILE
                        json output in file
~~~
  
Most of the options are pretty self-explanatory, however, I would like to draw your attention towards the following 3 options: 

`--region` this will allow you to specify a default region. If no region is selected it will enumerate over all regions. 
  
`--output-file` saves the results in json format
  
`--service` provide specific service that you want to enumerate 
  
You can run `--list-services` to list all the available service that this tool currently can enumerate

## Sample Output

![](/Sample_Output/aws_service_enum_sample_output.png)

## Author

* [Raunak Parmar](https://www.linkedin.com/in/trouble1raunak/)