import pandas as pd
import os
import re
import requests
from requests.auth import HTTPBasicAuth
import json
from netmiko import ConnectHandler
from webexteamssdk import WebexTeamsAPI


def device_information(csv_file):
    output_file = 'output.csv'
    df = pd.read_csv(csv_file)
    df = df.drop_duplicates(subset="IP address")

    df['OS type'] = ''

    version = re.compile(r'Cisco IOS Software.*,.*, Version (.*),')
    pid = re.compile(r'[C|c]isco\s+([A-Z]+[/-]?[A-Z0-9]{1,}[-/][A-Z0-9]{1,}).*bytes of memory')

    for index, row in df.iterrows():
        ip_address = row['IP address']
        ping_reply = os.system(f"ping -n 2 -w 1 {ip_address}")
        if ping_reply == 0:
            device = {
                'device_type': 'cisco_ios',
                'ip': ip_address,
                'username': 'admin',
                'password': 'cisco!123',
                'secret': 'cisco!123'
            }
            df.at[index, 'Reachability'] = 'Reachable'
            try:
                connection = ConnectHandler(**device)
                output = connection.send_command('show version')
                version_output = version.search(output).group(1)
                pid_output = pid.search(output).group(1)
                if "Cisco IOS-XE" in output:
                    df.at[index, 'OS type'] = "IOS-XE"
                else:
                    df.at[index, 'OS type'] = "IOS"
                df.at[index, 'Version'] = version_output
                df.at[index, 'PID'] = pid_output
                connection.disconnect()
            except Exception as e:
                print(f"Failed to retrieve info from {ip_address}: {str(e)}")
        else:
            df.at[index, 'Reachability'] = 'Unreachable'

    df.to_csv(output_file, index=False)



def proc_memory():
    csv_file = 'output.csv'
    output_file = 'output.csv'
    df = pd.read_csv(csv_file)
    df['Configured restconf']=  ''

    config_line = 'restconf'

    df['Memory Usage'] = ''

    for index, row in df.iterrows():
        ip_address = row['IP address']
        if row['OS type'] == 'IOS-XE':
            device = {
                'device_type': 'cisco_ios',
                'ip': ip_address,
                'username': 'admin',
                'password': 'cisco!123',
                'secret': 'cisco!123'
                }
            try:
                connection = ConnectHandler(**device)
                output = connection.send_command('show run')
                if config_line in output:
                    df.at[index, 'Configured restconf'] = "Restconf enabled"
                else:
                    df.at[index, 'Configured restconf'] = "No Restconf"
                    output = connection.send_config_set(config_line)
                    connection.exit_config_mode()
                    connection.disconnect()
            except Exception as e:
                print(f"Failed to retrieve info from {ip_address}: {str(e)}")
            
            headers = {
            "Accept": "application/yang-data+json",
                }
            
            url_mem = f"https://{ip_address}/restconf/data/Cisco-IOS-XE-memory-oper:memory-statistics"
            response = requests.get(url_mem, headers=headers, verify=False, auth=HTTPBasicAuth(device['username'], device['password']))
            
            if response.status_code == 200:
                response = response.json()
                memory_statistics = response['Cisco-IOS-XE-memory-oper:memory-statistics']['memory-statistic']
                for element in memory_statistics:
                    if element['name'] == 'Processor':
                        total_memory = element['total-memory']
                        used_memory = element['used-memory']
                        total_used_memory = (int(used_memory)/int(total_memory))*100
                        if total_used_memory > 90:
                            df.at[index, 'Memory Usage'] = f'ALERT! MEMORY USAGE EXCEED 90%'
                        else:
                            df.at[index, 'Memory Usage'] = f'{total_used_memory:.2f}%'
    
    df.to_csv(output_file, index=False)


#-----------------------------------------------------
token = ''
url = 'https://id.cisco.com/oauth2/default/v1/token'
data = {
    'client_id': '63ed3gpqg5jbrrmbdch6zd4d',
    'client_secret': 'fTrzZVVTAMP9AdcRTXPvbSyS',
    'grant_type': 'client_credentials',
        }
device_id = 'CISCO2951/K9'

response = requests.post(url=url, data=data)

if response.status_code == 200:
    token = response.json().get('access_token')
    
else:
    print(f'Request failed with status code {response.status_code}')

csv_file = 'output.csv'
output_file = 'output.csv'
df = pd.read_csv(csv_file)

df['Potential_bugs'] = ''

headers = {
    'Authorization': f'Bearer {token}'
}
#---------------------------------------------------------


def bug_information():

    for index, row in df.iterrows():
        device_id = row['PID']
        if device_id:
            try:
                url = f"https://apix.cisco.com/bug/v3.0/bugs/products/product_id/{device_id}?page_index=1&modified_date=5"
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    response_data = (response.json())
                    bug_id = [bug['bug_id'] for bug in response_data['bugs']]
                    df.at[index, 'Potential_bugs'] = bug_id
                else:
                    df.at[index, 'Potential_bugs'] = 'Wrong API access'
            except Exception as e:
                print(f"Failed to retrieve info from {device_id}: {str(e)}")

    csv_file = 'output.csv'
    df.to_csv(csv_file, index = False)



def psirt_information(data, api):
    csv_file = 'output.csv'
    df = pd.read_csv(csv_file)

    df['PSIRT'] = ''
    df['Critical PSIRT'] = ''
    
    for index, row in df.iterrows():
        version = row['Version']
        if device_id:
            try:
                url = f"https://apix.cisco.com/security/advisories/v2/OSType/iosxe?version={version}"
                response = requests.get(url, headers=headers)

                if response.status_code == 200:
                    response_data = (response.json())
                    
                    advisory_id = []
                    critical_advisory = []
                    for advisory in response_data['advisories']:
                        advisory_id.append(advisory['advisoryId'])
                        if float(advisory['cvssBaseScore']) >= 7.5:
                            critical_advisory.append(advisory['advisoryId'])
                    #df.at[index, 'PSIRT'] = advisory_id
                    df.at[index, 'Critical PSIRT'] = critical_advisory
                else:
                    print(f'Request failed with status code {response.status_code}')
                    #df.at[index, 'PSIRT'] = 'Wrong API access'
            except Exception as e:
                print(f'Failed to retrieve info from {device_id}: {str(e)}')
    
    df.to_csv(csv_file, index = False)

    # Send the output file as a message in Webex Teams
    room_id = data['data']['roomId']
    message = "Aquí está tu archivo editado"
    api.messages.create(roomId=room_id, text=message, files=[output_file])