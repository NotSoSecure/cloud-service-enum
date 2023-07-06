`gcp_service_enum.py` let you discover gcp services by providing service account key file

## Requirements

* Service account key needs to be provided as arguments. In some cases projectId, projectNo are also required
* pip install -r requirements.txt will install all necessary python packages.

## Usage
~~~
usage: gcp_enum_services.py [-h] -f F [--output-file OUTPUT_FILE]

options:
  -h, --help            show this help message and exit
  -f F                  Provide service account key file Json file
  --output-file OUTPUT_FILE
                        Provide output file path (Optional)
~~~

## Sample Output

![](/Sample_Output/gcp_service_enum_sample_output.png)

## Author

* [Raunak Parmar](https://www.linkedin.com/in/trouble1raunak/)