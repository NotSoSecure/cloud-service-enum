import requests, json
from argparse import ArgumentParser
from tabulate import tabulate
from crayons import blue, yellow, red, green
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

parser = ArgumentParser()
parser.add_argument('--access-token', help='Provide Azure Management Access token', required=True)
parser.add_argument('--output-file', help='Provide output file path (Optional)', required=False)
args = parser.parse_args()

# Create a session with retry mechanism
session = requests.Session()
retry_strategy = Retry(total=10, backoff_factor=0.5)
adapter = HTTPAdapter(max_retries=retry_strategy)
session.mount('http://', adapter)
session.mount('https://', adapter)

jsonOutputs = []

def http_request(url, headers):
    response = session.get(url, headers=headers)
    response.raise_for_status()
    return response.json()


def list_azure_data(access_token):
    headers = {
        'Authorization': 'Bearer ' + access_token,
        'Content-Type': 'application/json'
    }

    subscriptions_url = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
    try:
        subscriptions_data = http_request(subscriptions_url, headers)
    except Exception as e:
        print(red("[!] Error Found: Access Token expired or invalid.", bold=True))
        exit()

    if 'value' in subscriptions_data:
        subscriptions = subscriptions_data['value']
        subscription_table = []

        for subscription in subscriptions:
            subscription_id = subscription['subscriptionId']
            subscription_display_name = subscription['displayName']
            subscription_table.append([subscription_id, subscription_display_name])
            resource_groups_url = f'https://management.azure.com/subscriptions/{subscription_id}/resources?api-version=2020-06-01'
            services_data = http_request(resource_groups_url, headers)
            
            if 'value' in services_data:
                services = services_data['value']
                services_table = []

                for service in services:
                    service_Id = service['id']
                    service_name = service['name']
                    service_type = service['type']
                    service_resource_group = service_Id.split("/")[4]
                    services_table.append([service_name, service_type, service_resource_group])

                if services_table:
                    print(yellow(f"Subscription: {subscription_display_name} ({subscription_id})", bold=True))
                    print(tabulate(services_table, headers=[blue('Service Name', bold=True), blue('Service Type', bold=True), blue('Resource Group', bold=True)], tablefmt='psql'))
                    print()
                    json_data = {
                        "subscriptionID":subscription_id,
                        "subscriptionDisplayName":subscription_display_name,
                        "resources":services_data['value'],
                    }
                    jsonOutputs.append(json_data)


        if subscription_table:
            print(yellow("Listing Subscriptions:", bold=True))
            print(tabulate(subscription_table, headers=[blue('Subscription ID', bold=True), blue('Subscription Name', bold=True)], tablefmt='psql'))
            print()
        else:
            print(red("No subscriptions found. 1", bold=True))
    else:
        print(red("No subscriptions found.2", bold=True))

    # Save JSON object to file
    if args.output_file:
        with open(args.output_file, 'w') as file:
            json.dump(jsonOutputs, file, indent=4)
        print()
        print(green(f'Azure data saved to {args.output_file}', bold=True))
        print()


list_azure_data(args.access_token)
