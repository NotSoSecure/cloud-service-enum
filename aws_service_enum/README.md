
`AWS_SERVICE_ENUM` let you discover aws services which a following set of credentials has access to (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) and then checks for associated buckets to discovered services. 

This tool is helpful in scenarios where you got AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`) through SSRF or any other vulnerability, but you are not sure if given credentials have access to other services or not. Instead of just trying for top 10 aws services (s3, ec2, etc), you can run this tool and it will let you enumerate through each non-intrusive(For example, only listing buckets, this tool won't be creating/modifying bucket) feature of each service. 

## Requirements

* `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`
* `pip install -r requirements.txt`

## Usage

~~~
usage: aws_service_enum.py [-h] --access-key --secret-key --session-token
                   [--region] [--verbose] [--s3-enumeration] [--logs]

< AWS_SERVICE_ENUM Says "Hello, world!" >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/
                ||----w |
                ||     ||

required arguments:
  --access-key     AWS Access Key ID
  --secret-key     AWS Secret Key
  --session-token  AWS Security Token

optional arguments:
  -h, --help         show this help message and exit
  --region         Enter any value from given list
                     ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-southeast-1, ap-southeast-2, ap-south-1
                     ca-central-1
                     eu-central-1, eu-west-1, eu-west-2, eu-west-3, eu-north-1
                     us-east-1, us-east-2, us-west-1, us-west-2
                     sa-east-1
  --verbose          Select for Verbose output
  --s3-enumeration   Enumerate possible S3 buckets associated with services like ElasticBeanstalk, Athena
  --logs             Create a log File
  ~~~
  
Most of the options are pretty self-explanatory, however, I would like to draw your attention towards the following 3 options: 

`--region` this will allow you to specify a default region. If no region is selected it will enumerate over all regions. 
  
`--logs` creates a log file in the same directory. 
  
`--s3-enumeration` is quite interesting feature here. In our earlier research on [AWS Beanstalk](https://www.notsosecure.com/exploiting-ssrf-in-aws-elastic-beanstalk/) we discovered that AWS by default uses naming patters while creating a bucket. 
  
For example, if you create a elasticbeanstalk service then AWS will create a bucket like `elasticbeanstalk-REGIONNAME-ACCOUNTID`, where REGIONNAME is region of elastic beanstalk and ACCOUNTID is account id of the role. 
 
`--s3-enumeration` will list all buckets which discovered service has access to but are not accessible directly. For example, if you discovered elasticbeanstalk credentials through SSRF, if you use same credentials to do `aws s3 ls`, it will not list associated buckets to service. But if you use `--s3-enumeration`, it will try to guess the bucket and if there is a bucket, it will list(only list) out the content of the bucket as well. 

## Sample Output

![](/Sample_Output/aws_service_enum_sample_output.png)


