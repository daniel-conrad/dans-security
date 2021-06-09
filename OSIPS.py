import requests
import json
import pandas as pd
from config import ABUSEIPDB_API_KEY, VT_API_KEY, VOID_API_KEY

# Receive IP for analysis
print("#### OSIPS Project - IP Analysis ####")
print("Created by Daniel Conrad")
print("\n")
print("Enter a valid IP here...")
ip = input('')

# Defining the api-endpoints
abuse_url = 'https://api.abuseipdb.com/api/v2/check'
vt_url = (f'https://www.virustotal.com/api/v3/ip_addresses/{ip}')
void_url = (f'https://endpoint.apivoid.com/iprep/v1/pay-as-you-go/?key={VOID_API_KEY}&ip={ip}')


abuse_querystring = {
    'ipAddress': ip,
    'maxAgeInDays': '365'
}

abuse_headers = {
    'Accept': 'application/json',
    'Key': ABUSEIPDB_API_KEY
}

vt_querystring = {
    'ip': ip
}

vt_headers = {
    'Accept': 'application/json',
    'X-APIKey': VT_API_KEY
}

abuse_response = requests.request(method='GET', url=abuse_url, headers=abuse_headers, params=abuse_querystring)
vt_response = requests.request(method='GET', url=vt_url, headers=vt_headers, params=vt_querystring)
void_response = requests.request(method='GET', url=void_url)

# Formatted output
abuse_decodedResponse = json.loads(abuse_response.text)
vt_decodedResponse = json.loads(vt_response.text)
void_decodedResponse = json.loads(void_response.text)

# Variable Madness (Define Variables)
address = (abuse_decodedResponse['data']['ipAddress'])
confidence = (abuse_decodedResponse['data']['abuseConfidenceScore'])
country = (abuse_decodedResponse['data']['countryCode'])
hostname = (abuse_decodedResponse['data']['hostnames'])
isp = (abuse_decodedResponse['data']['isp'])
whitelist = (abuse_decodedResponse['data']['isWhitelisted'])
totalreports = (abuse_decodedResponse['data']['totalReports'])
usage = (abuse_decodedResponse['data']['usageType'])

harmless = (vt_decodedResponse['data']['attributes']['last_analysis_stats']['harmless'])
malicious = (vt_decodedResponse['data']['attributes']['last_analysis_stats']['malicious'])
suspicious = (vt_decodedResponse['data']['attributes']['last_analysis_stats']['suspicious'])

tor = (void_decodedResponse['data']['report']['anonymity']['is_tor'])
vpn = (void_decodedResponse['data']['report']['anonymity']['is_vpn'])
void_detection = (void_decodedResponse['data']['report']['blacklists']['detection_rate'])
region = (void_decodedResponse['data']['report']['information']['region_name'])
city = (void_decodedResponse['data']['report']['information']['city_name'])
latitude = (void_decodedResponse['data']['report']['information']['latitude'])
longitude = (void_decodedResponse['data']['report']['information']['longitude'])

#Make Pandas Dataframe look "crispy"
ip_data = {'Category':  ['IP Address',
                         'ISP',
                         'Country',
                         'Region / State',
                         'City',
                         'Whitelisted',
                         'Total Times Reported',
                         'Usage',
                         'Abuse IPDB Score',
                         'VT Considered Harmless',
                         'VT Considered Malicious',
                         'VT Considered Suspicious',
                         'TOR',
                         'VPN',
                         'API VOID Detection Rate'
                         ],
               'Values': [address,
                          isp,
                          country,
                          region,
                          city,
                          whitelist,
                          totalreports,
                          usage,
                          confidence,
                          harmless,
                          malicious,
                          suspicious,
                          tor,
                          vpn,
                          void_detection,
                        ]
              }

# Generate dataframe
ip_results = pd.DataFrame (ip_data, columns = ['Category','Values'])

# Output to Excel file
print(f"File Created: {ip} Results.xlsx")
writer = pd.ExcelWriter(f"{ip} Results.xlsx")
ip_results.to_excel(writer, sheet_name=(f"{ip} Results.xlsx"), index=False, na_rep='NaN')

# Auto-adjust columns' width
for column in ip_results:
    column_width = max(ip_results[column].astype(str).map(len).max(), len(column))
    col_idx = ip_results.columns.get_loc(column)
    writer.sheets[(f"{ip} Results.xlsx")].set_column(col_idx, col_idx, column_width)

writer.save()
