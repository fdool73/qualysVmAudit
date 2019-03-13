import requests
import xml.etree.ElementTree as ET

def Diff(requirements, result):
    return (list(set(requirements) - set(result)))


username = "xxxxxxx"
password = "xxxxxxx"

headers = {
    'X-Requested-With':'Qualys API',
    }

login = {
  'action':'login',
  'username':username,
  'password':password
}

#session = requests.Session()
with requests.Session() as session:
    r = session.post('https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/session/', headers=headers, data=login)

    #Option Profile
    optionProfile = session.get('https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/subscription/option_profile/?action=export', headers=headers)

    xml_data_op = ET.fromstring(optionProfile.text)

    for profile in xml_data_op:
        optionProfileRequirements = [
            '<TCP_PORTS_TYPE>full</TCP_PORTS_TYPE>','<UDP_PORTS_TYPE>standard</UDP_PORTS_TYPE>',
            '<OVERALL_PERFORMANCE>Normal</OVERALL_PERFORMANCE>','<LOAD_BALANCER_DETECTION>1</LOAD_BALANCER_DETECTION>',
            '<PASSWORD_BRUTE_FORCING><SYSTEM><HAS_SYSTEM>1</HAS_SYSTEM><SYSTEM_LEVEL>Standard</SYSTEM_LEVEL></SYSTEM></PASSWORD_BRUTE_FORCING>',
            '<TITLE><![CDATA[NIMBUS SSH LIST]]></TITLE>','<VULNERABILITY_DETECTION><COMPLETE><![CDATA[complete]]></COMPLETE>',
            '<BASIC_INFO_GATHERING_ON>all</BASIC_INFO_GATHERING_ON>','<TCP_PORTS_STANDARD_SCAN>1</TCP_PORTS_STANDARD_SCAN>',
            '<PERFORM_LIVE_HOST_SWEEP>1</PERFORM_LIVE_HOST_SWEEP>','<OVERALL_PERFORMANCE>Normal</OVERALL_PERFORMANCE>',
            '<ADDITIONAL><HOST_DISCOVERY><TCP_PORTS><STANDARD_SCAN>1</STANDARD_SCAN> </TCP_PORTS>','<ADDITIONAL><HOST_DISCOVERY><UDP_PORTS><STANDARD_SCAN>1</STANDARD_SCAN></UDP_PORTS>',
            '<ICMP>1</ICMP>'
        ]
        profile_string = ET.tostring(profile).decode()
        profile_list = [line.strip() for line in profile_string.split()]
        print("Missing values in Option Profile: ","\n".join(Diff(optionProfileRequirements, profile_list)))

    #Scanner Appliance
    scannerAppliance = session.get('https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/appliance/?action=list', headers=headers, data={'action':'list', 'output_mode':'full'})

    xml_data_sa = ET.fromstring(scannerAppliance.text)

    for profile in xml_data_sa:
        scannerApplianceRequirements = [
        '<STATUS>Online</STATUS>','<NAME>Global EC2 Network</NAME>','<SOFTWARE_VERSION>2.6</SOFTWARE_VERSION>'
        ]

        scanner_string = ET.tostring(profile).decode()
        scanner_list = [line.strip() for line in scanner_string.split()]
        print("Missing values in Scanner Appliance: ","\n".join(Diff(scannerApplianceRequirements, scanner_list)))

    #Asset Tags
    assetTags = session.post('https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/search/am/assetdataconnector/', headers=headers)

    xml_data_at = ET.fromstring(assetTags.text)

    for profile in xml_data_at:
        assetTagRequirements = ['<type>AWS</type>']
        asset_string = ET.tostring(profile).decode()
        asset_list = [line.strip() for line in asset_string.split()]
        print("Missing values in Asset Tags: ","\n".join(Diff(assetTagRequirements, asset_list)))

    #EC2 Connectors
    #Requires POST of XML (payload below)
    url = "https://qualysapi.qg3.apps.qualys.com/qps/rest/2.0/search/am/assetdataconnector/"

    payload = "<ServiceRequest>\n<filters>\n<Criteria field=\"activation\" operator=\"EQUALS\">VM</Criteria>\n</filters>\n</ServiceRequest>"
    headers = {
        'X-Requested-With': "Qualys API",
        'Content-Type': "text/xml"
        }
    response = requests.request("POST", url, data=payload, headers=headers)
    xml_data_ec = ET.fromstring(response.text)

    for profile in xml_data_ec:
        ec2ConnectRequirements = ['<type>AWS</type>']
        ec2_string = ET.tostring(profile).decode()
        ec2_list = [line.strip() for line in ec2_string.split()]
        print("Missing values in EC2 Connectors: ","\n".join(Diff(ec2ConnectRequirements, ec2_list)))

    #Excluded Hosts
    excludedHosts = session.get('https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/asset/excluded_ip/?action=list', headers=headers, data={'action':'list'})

    xml_data_eh = ET.fromstring(excludedHosts.text)

    for profile in xml_data_eh:
        excludedHostsRequirements = ['<IP_LIST_OUTPUT>','</IP_LIST_OUTPUT>']
        hosts_string = ET.tostring(profile).decode()
        hosts_list = [line.strip() for line in hosts_string.split()]
        print("Missing values in Excluded Hosts: ","\n".join(Diff(excludedHostsRequirements, hosts_list)))

    #Scheduled Scans
    scheduledScan = session.get('https://qualysapi.qg3.apps.qualys.com/api/2.0/fo/schedule/scan/?action=list', headers=headers, data={'action':'list', 'show_cloud_details=':'1'})

    xml_data_scan = ET.fromstring(scheduledScan.text)

    for profile in xml_data_scan:
        scheduledScansRequirements = [
            '<TITLE><![CDATA[AWS EC2 Perimeter Scan]]></TITLE>','<OPTION_PROFILE><TITLE><![CDATA[Initial Options]]></TITLE><DEFAULT_FLAG>1</DEFAULT_FLAG> </OPTION_PROFILE>',
            '<CONNECTOR_UUID></CONNECTOR_UUID>','<EC2_ENDPOINT></EC2_ENDPOINT>''<DAILY frequency_days="1" />'
        ]
        scan_string = ET.tostring(profile).decode()
        scan_list = [line.strip() for line in scan_string.split()]
        print("Missing values in Scheduled Scan: ","\n".join(Diff(scheduledScansRequirements, scan_list)))
