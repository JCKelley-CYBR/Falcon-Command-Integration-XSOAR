register_module_line('Falcon-Command-Integration', 'start', __line__())
#######################
# Description: CrowdStrike Falcon API Integration - For executing custom CrowdStrike commands
# Author: Joshua Kelley
# Creation: June 2023
#######################
 
from falconpy import APIHarness
import urllib3
from time import sleep
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
 
CLIENT_ID = demisto.params().get('credentials', {}).get('identifier') or demisto.params().get('client_id')
CLIENT_SECRET = demisto.params().get('credentials', {}).get('password') or demisto.params().get('secret')
 
######################
# Description: Test connection to CrowdStrike Falcon API
# Parameters: None
# Returns: Success or Failure message to Demisto
######################
def test_module():
    try:
        falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)
        response = falcon.command("GetSensorInstallersByQuery", limit=1)
    except ValueError:
        return 'Connection Error: The URL or The API key you entered is probably incorrect, please try again.'
    return 'ok'
 
######################
# Description: Falcon-MassContainment functions
# functions: GetHosts, HostAction, MassContainment
#            GetHosts - Get Hosts from CrowdStrike filtered by site name
#            HostAction - Take action on Hosts in CrowdStrike (contain, lift_containment)
#            MassContainment - Main function to call GetHosts and HostAction
# Parameters: falcon - Falcon API Harness
#             filter_name - field to filter by
#             query - value to filter by
# Returns: CrowdStrike API response and AID of target hosts
######################
def GetHosts(falcon, query, filter_name, action):
    max_limit = 500
    total = 1
    offset = ""
    all_ids = []
    batchresults = []
    status = 200
    batch_count = 0
    while len(all_ids) < total and status == 200:
        batch_count += 1
        filter_string = filter_name +":'" + query + "'"
        response = falcon.command("QueryDevicesByFilterScroll",
                                  filter=filter_string,
                                  limit=max_limit,
                                  offset=offset
                                  )
        status = response["status_code"]
        if status == 200:
            result = response["body"]
            offset = result["meta"]["pagination"]["offset"]
            total = result["meta"]["pagination"]["total"]
            id_list = result["resources"]
            all_ids.extend(id_list)
 
            batchaction = HostAction(falcon, id_list, action)
 
            if batchaction["status_code"] == 202:
                batchresults.append("Batch action successful: " + action)
            else:
                batchresults.append("Batch " + batch_count + " action failed." + batchaction["body"]["errors"][0]["message"])
 
            if len(all_ids) == total:
                print("All IDs Collected")
                return batchresults
        else:
            for error_result in response["body"]["errors"]:
                print(error_result["message"])
    return "Batch " + batch_count + " action failed."
 
def HostAction(falcon, hostlist, action):
    response = falcon.command("PerformActionV2", action_name=action, body={"ids": hostlist})
    return response
 
def MassContainment(action, filter_name, query):
    falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)
    response = GetHosts(falcon, query, filter_name, action)
    return response
 
######################
# Description: GetLoggedIn to retrieve a dictionary of the most recent loggins from a host
# Parameters: falcon - Falcon API Harness
#             hostname - hostname of target host
#             agent_id - AID of target host
# Returns: Dictionary of the most recent loggins from a host
######################
def GetAgentID(falcon, hostname):
    response = falcon.command("QueryDevicesByFilterScroll"
                          ,limit=1
                          ,filter="hostname:'" + hostname + "'"
                          )
    return response["body"]["resources"][0]
 
def QueryLoggins(falcon, agent_id):
    BODY = {
        "ids": [
            agent_id
        ]
    }
    response = falcon.command("QueryDeviceLoginHistory", body=BODY)
    return response["body"]["resources"][0]
 
def gliMarkdown(data, hostname):
    records = []
    aid = data["device_id"]
    for record in data["recent_logins"]:
        selected_record = {
            "Hostname": hostname
            ,"UserName": record["user_name"]
            ,"Login Time": record["login_time"]
            ,"Device ID": aid
        }
        records.append(selected_record)
    return records
 
def GetLoggedIn(hostname):
    falcon = APIHarness(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    aid = GetAgentID(falcon, hostname)
    response = QueryLoggins(falcon, aid)
    results = gliMarkdown(response, hostname)
    markdown = tableToMarkdown('Recent Logins', results, headers=['Hostname', 'UserName', 'Login Time', 'Device ID'])
    results = CommandResults(
        readable_output=markdown
        ,outputs_prefix='Falcon.HostLogins'
        ,outputs_key_field='UserName'
        ,outputs=results
    )
    return results
 
######################
# Description: NewIOC to create a new IOC in CrowdStrike
def NewIOC():
    comment = demisto.args()['comment']
    action = demisto.args()['action']
    description = demisto.args()['description']
    platform_list = demisto.args()['platform_list']
    ioc_severity = demisto.args()['ioc_severity']
    ioc_source = demisto.args()['ioc_source']
    ioc_tags = demisto.args()['ioc_tags']
    ioc_type = demisto.args()['ioc_type']
    ioc_value = demisto.args()['ioc_value']
    filename = demisto.args()['filename']
    platform_list = platform_list.split(",")
    ioc_tags = ioc_tags.split(",")
    falcon = APIHarness(client_id=CLIENT_ID,client_secret=CLIENT_SECRET)
    BODY = {
        "comment": comment,
        "indicators": [
            {
            "action": action,
            "applied_globally": True,
            "description": description,
            "metadata": {
                "filename": filename,
            },
            "platforms": platform_list,
            "severity": ioc_severity,
            "source": ioc_source,
            "tags": ioc_tags,
            "type": ioc_type,
            "value": ioc_value
            }
        ]
    }
    response = falcon.command("indicator_create_v1"
                              ,body=BODY
                              ,retrodetects=True
                              ,ignore_warnings=False
                              )
    return response["status_code"]
 
######################
# Description: GetLocalIp to retrieve a dictionary of device Local IPs from CrowdStrike
# Parameters: falcon - Falcon API Harness
#             hostlist - list of AIDs to get IP addresses for
# Returns: Dictionary of device Local IPs from CrowdStrike
######################
def GetIP(falcon, hostlist):
    response = falcon.command("GetDeviceDetailsV2", ids=hostlist)
    code = response['status_code']
    response = response["body"]["resources"]
    if code == 200:
        ips = {}
        for device in response:
            ips[device["hostname"]] = device["local_ip"]
        return ips
    else:
        print("Error getting IP addresses from Falcon API")
        return response
 
def GetLocalIp(hosts):
    falcon = APIHarness(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    hostlist = []
    for host in hosts.split(","):
        host = host.strip()
        aids = GetAgentID(falcon, host)
        hostlist.append(aids)
    ips = GetIP(falcon, hostlist)
    return ips
 
######################
# Description: GetUserHosts to retrieves the hosts associated with a user
# Parameters: id - samAccountName of user
# Returns: Dictionary of hosts associated with a user, and some details about the hosts
######################
def GetUserHosts(id):
    falcon = APIHarness(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
    
    idp_query = '''
    {
        entities(secondaryDisplayNames:"YOURDOMAIN\\\\REPLACEME", first:1) {
            nodes {
                name: primaryDisplayName
                UserName: secondaryDisplayName
                logins: associations(bindingTypes: [LOGIN])
                {
                    ... on EntityAssociation
                    {
                        entity
                        {
                            endpoint: primaryDisplayName,
                            endpointSecondaryName: secondaryDisplayName
                            ... on EndpointEntity {
                                mostRecentActivity
                                lastIpAddress
                            }
                        }
                    }
                }
            }
        }
    }
    '''
    
    idp_query = idp_query.replace("REPLACEME", id)
 
    variables = {
        "string": "string, int, float"
    }
 
    BODY = {
        "query": idp_query
        ,"variables": variables
    }
 
    response = falcon.command("api_preempt_proxy_post_graphql", body=BODY)
    return response['body']['data']['entities']['nodes'][0]
 
######################
# Description: guhMarkdown to convert GetUserHosts response to markdown table for Demisto war room
# Parameters: data - GetUserHosts response
# Returns: Markdown table of hosts associated with a user, and some details about the hosts
######################
def guhMarkdown(data):
    selected_records = []
    UserName = data['UserName']
    UserName = UserName.split("\\")[-1]
    for record in data['logins']:
        selected_record = {
            "Endpoint": record['entity']['endpoint']
            ,"UserName": UserName
            ,"Last Endpoint Activity": record['entity']['mostRecentActivity']
            ,"Last Endpoint IP": record['entity']['lastIpAddress']
        }
        selected_records.append(selected_record)
    return selected_records
 
######################
# Description: Main function
# Parameters: None
# Returns: Success or Failure message to Demisto console/playground
######################
def main():
    command = demisto.command()
    try:
        if command == 'test-module':
            result = test_module()
            return_results(result)
        elif command == 'Falcon-Contain':
            action = demisto.args()['action']
            filter_name = demisto.args()['filter_name']
            query = demisto.args()['query']
            return_results(MassContainment(action, filter_name, query))
        elif command == 'Falcon-GetLoggedIn':
            hostname = demisto.args()['hostname']
            return_results(GetLoggedIn(hostname))
        elif command == 'Falcon-NewIOC':
            return_results(NewIOC())
        elif command == 'Falcon-GetLocalIp':
            hosts = demisto.args()['hostname']
            return_results(GetLocalIp(hosts))
        elif command == 'Falcon-GetUserHost':
            id = demisto.args()['samAccountName']
            data = GetUserHosts(id)
            logins = guhMarkdown(data)
            markdown = tableToMarkdown('User Hosts', logins, headers=['Endpoint', 'UserName', 'Last Endpoint Activity', 'Last Endpoint IP'])
            results = CommandResults(
                readable_output=markdown
                ,outputs_prefix='Falcon.UserHost'
                ,outputs_key_field='Endpoint'
                ,outputs=logins
            )
            return_results(results)
        else:
            raise NotImplementedError(f'CrowdStrike Falcon error: '
                                      f'command {command} is not implemented')
    except Exception as e:
        return_error(str(e))
    pass
 
if __name__ in ('__main__', 'builtin', 'builtins'):
    main()
 
register_module_line('Falcon-Command-Integration', 'end', __line__())