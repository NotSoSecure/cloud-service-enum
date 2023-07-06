`azure_service_enum.py` let you discover Azure services which through management access token.
This tool is helpful in scenarios where you got “ARM access token” through command injection or any other vulnerability, but you are not sure if given credentials have access to other services or not. Instead of just trying for top few azure services (buckets, compute VM, etc), you can run this tool and it will let you enumerate through each non-intrusive(For example, only listing storage Accounts, this tool won't be creating/modifying bucket) features of each service.

## Requirements
* Management access token needs to be provided as arguments.
* `pip install -r requirements.txt` will install all necessary python packages.

## Usage

~~~
usage: azure_service_enum.py [-h] --access-token ACCESS_TOKEN [--output-file OUTPUT_FILE]

options:
  -h, --help            show this help message and exit
  --access-token ACCESS_TOKEN
                        Provide Azure Management Access token
  --output-file OUTPUT_FILE
                        Provide output file path (Optional)
~~~

## Sample Output

![](/Sample_Output/azure_service_enum_sample_output.png)

## Author

* [Raunak Parmar](https://www.linkedin.com/in/trouble1raunak/)