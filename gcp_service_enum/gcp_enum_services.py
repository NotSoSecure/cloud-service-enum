from crayons import red, green, yellow, blue
from tabulate import tabulate
from google.oauth2 import service_account
from google.cloud import resource_manager, compute_v1, storage, functions_v2
import argparse, json

parser = argparse.ArgumentParser()
parser.add_argument('-f',  help='Provide service account key file Json file', required=True)
parser.add_argument('--output-file', help='Provide output file path (Optional)', required=False)

args = parser.parse_args()

json_body = {}

def list_gcp_data(service_account_file):
    # Load service account credentials
    try:
        credentials = service_account.Credentials.from_service_account_file(service_account_file)
    except Exception as e:
        print(red("[-] Invalid file!"))
        exit()    

    # Initialize Resource Manager client
    client = resource_manager.Client(credentials=credentials)

    # List projects
    print(blue("Listing Projects:", bold=True))
    projects = list(client.list_projects())
    project_table = []
    for project in projects:
        project_id = project.project_id
        project_name = project.name
        project_table.append([project_id, project_name])
    print_table(project_table, headers=['Project ID', 'Project Name'])
    print()

    # List resources for each project
    for project in projects:
        project_id = project.project_id
        project_name = project.name
        print(blue(f"Project: {project_name} ({project_id})", bold=True))
        print(yellow("Resources:", bold=True))

        # List resource types
        resource_types = ['cloud_storage','instances', 'disks', 'networks', 'buckets', 'firewalls', 'cloudfunctions', 'cloudsql']  
        for resource_type in resource_types:
            resources = list_resources(project_id, resource_type, credentials)
            resource_table = []
            for resource in resources:
                
                if resource_type == 'instances':
                    resource_name = resource.name
                elif resource_type == 'disks':
                    resource_name = resource.name
                else:
                    resource_name = resource
                resource_table.append([resource_name])
                
                try:
                    json_body[resource_name].append(resource_name)
                except:
                    json_body[resource_name] = []
                    json_body[resource_name].append(resource_name)
            if resource_table:
                print(green(f"\n{resource_type.capitalize()}:", bold=True))
                print_table(resource_table, headers=[resource_type.capitalize()])

        print()

def list_resources(project_id, resource_type, credentials):
    if resource_type == 'instances':
        client = compute_v1.InstancesClient(credentials=credentials)
        response = client.list(request={"project": project_id, "zone": "us-central1-a"})
        return response.items
    elif resource_type == 'disks':
        client = compute_v1.DisksClient(credentials=credentials)
        response = client.list(request={"project": project_id, "zone": "us-central1-a"})
        return response.items
    elif resource_type == 'networks':
        client = compute_v1.NetworksClient(credentials=credentials)
        response = client.list(request={"project": project_id})
        return [network.name for network in response.items]
    elif resource_type == 'buckets':
        client = storage.Client(credentials=credentials)
        buckets = client.list_buckets(project=project_id)
        return [bucket.name for bucket in buckets]
    elif resource_type == 'firewalls':
        client = compute_v1.FirewallsClient(credentials=credentials)
        response = client.list(request={"project": project_id})
        return [firewall.name for firewall in response.items]
    elif resource_type == 'cloud_storage':
        client = storage.Client(credentials=credentials)
        buckets = client.list_buckets(project=project_id)
        return [bucket.name for bucket in buckets]
    elif resource_type == 'cloudfunctions':
        client = functions_v2.FunctionServiceClient(credentials=credentials)
        # List functions
        parent = f"projects/{project_id}/locations/-"
        functions = client.list_functions(parent=parent)
        return [function.name for function in functions]
    else:
        return []

def print_table(data, headers):
    # Print data in table format
    if data:
        print(tabulate(data, headers=headers, tablefmt='psql'))
    else:
        print("\tNo resources found.")

# Example usage
service_account_file = 'gcp-audit.json'
list_gcp_data(args.f)


if args.output_file:
    with open(args.output_file, 'w') as file:
        json.dump(json_body, file, indent=4)
    
    print()
    print(green(f'GCP data saved to {args.output_file}', bold=True))
    print()