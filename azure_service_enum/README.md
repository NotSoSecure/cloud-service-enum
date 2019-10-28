`azure_service_enum` let you discover Azure services which a  “Oauth Access Token” have access to. 
This tool is helpful in scenarios where you got “Oauth Access Token” through command injection or any other vulnerability, but you are not sure if given credentials have access to other services or not. Instead of just trying for top few azure services (buckets, compute VM, etc), you can run this tool and it will let you enumerate through each non-intrusive(For example, only listing buckets, this tool won't be creating/modifying bucket) features of each service.

## Requirements
* Oauth access token needs to be provided as arguments.
* pip install -r requirements.txt will install all necessary python packages.

## Usage

~~~
usage: azure_service_enum.py [-h] --access-token [--logs]

< Azure_SERVICE_ENUM Says "Hello, world!" >
 ---------------
        \   ^__^
         \  (oo)\_______
            (__)\       )\/
                ||----w |
                ||     ||

required arguments:
  --access-token  Azure Managed Identities Access Token

optional arguments:
  -h, --help        show this help message and exit
  --logs            Create a log File in same directory
~~~

## Sample Output

![](/Sample_Output/azure_service_enum_sample_output.png)
