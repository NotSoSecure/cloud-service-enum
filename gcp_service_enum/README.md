`GCP_service_enum` let you discover gcp services which a  “Oauth Access Token” have access to. 
This tool is helpful in scenarios where you got “Oauth Access Token” through SSRF or any other vulnerability, but you are not sure if given credentials have access to other services or not. Instead of just trying for top few gcp services (buckets, compute engine, etc), you can run this tool and it will let you enumerate through each non-intrusive(For example, only listing buckets, this tool won't be creating/modifying bucket) features of each service.

## Requirements

* Oauth access token needs to be provided as arguments. In some cases projectId, projectNo are also required
* pip install -r requirements.txt will install all necessary python packages.

## Usage
~~~
usage: gcp_service_enum.py [-h] --access-token [--region] [--project-id] [--verbose]
               [--logs]

< GCP_SERVICE_ENUM Says "Hello, world!" >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/
                ||----w |
                ||     ||

required arguments:
  --access-token  GCP oauth Access Token

optional arguments:
  -h, --help        show this help message and exit
  --region        Enter any value from given list
                    ap-northeast-1, ap-northeast-2, ap-northeast-3, ap-southeast-1, ap-southeast-2, 

ap-south-1, ca-central-1
                    eu-central-1, eu-west-1, eu-west-2, eu-west-3, eu-north-1
                    us-east-1, us-east-2, us-west-1, us-west-2
                    sa-east-1
  --project-id    ProjectID
  --verbose         Select for Verbose output
  --logs            Create a log File in same directory
  
~~~

## Sample Output

![](/Sample_Output/gcp_service_enum_sample_output.png)

## Authors

* Aditya Agrawal
* Dharmendra Gupta
