import requests
from bs4 import BeautifulSoup as bs
import json

requests.packages.urllib3.disable_warnings()
APIKey_file = open('../nessus_APIKey.txt','r').readlines()
AccessKey = APIKey_file[0][:-1].split(":")[1]
SecretKey = APIKey_file[1].split(":")[1]
header = {'X-ApiKeys': 'accessKey={accesskey};secretKey={secretkey}'.format(accesskey=AccessKey, secretkey=SecretKey),
          'Content-type': 'application/json',
          'Accept': 'text/plain'}

"""
Credential header sample
'credentials': {
    'edit': {
      '7': {
        'username': 'user',
        'password': '********',
        'domain': 'test.local',
        'auth_method': 'Password'
      }
    }
  }
"""

def get_polices(header):
    url = "https://192.168.232.139:8834/policies"
    respon = requests.get(url, headers=header, verify=False)
    if respon.status_code == 200:
        result = json.loads(respon.text)
    return result

def changepassword(uname,pwd,polices):
    logID = list(polices['credentials']['edit'].keys())[0]
    polices['credentials']['edit'][logID]['username'] = uname
    polices['credentials']['edit'][logID]['password'] = pwd
    print(polices['credentials'])
    return polices
    
def get_polices_detail(id):
    result = ''
    url = "https://192.168.232.139:8834/policies/%d"%id
    respon = requests.get(url, headers=header, verify=False)
    if respon.status_code == 200:
        result = json.loads(respon.text)
    return result
    
def copy_newpolicy(id):
    result = ''
    url = "https://192.168.232.139:8834/policies/%d/copy"%id
    respon = requests.post(url, headers=header, verify=False)
    if respon.status_code == 200:
        result = json.loads(respon.text)
    return result
    
def change_offices(id,polices):
    result = ''
    url = "https://192.168.232.139:8834/policies/%d"%id
    header = {'X-ApiKeys': 'accessKey={accesskey};secretKey={secretkey}'.format(accesskey=AccessKey, secretkey=SecretKey),
          'Content-type': 'application/json',
          'Accept': 'text/plain'}
    respon = requests.put(url, headers=header, verify=False, data=json.dumps(polices))
    print(respon.text)
    
    
"""
Input we need:
    {
        "uuid": {template_uuid},
        "settings": {
            "name": {string},
            "description": {string},
            "emails": {string},
            "enabled": "true",
            "launch": {string},
            "folder_id": {integer},
            "policy_id": {integer},
            "scanner_id": {integer},
            "text_targets": {string},
            "agent_group_id": []
        }
    }
"""
def assign_scan(new_uuid, police_id):
    url = "https://192.168.232.139:8834/scans"
    scan_detail ={
        'uuid': '{template_uuid}'.format(template_uuid = new_uuid),
        "settings": {
            "name":'{name}'.format(name = "API Crafted Scan"),
            "description":'{description}'.format(description = "Just a test scan"),
            "enabled": "true",
            "launch":'{launch}'.format(launch = "ON_DEMAND"),
            "policy_id":'{policy_id}'.format(policy_id = police_id),
            "text_targets":'{text_targets}'.format(text_targets = "10.11.1.230"),
            "agent_group_id": []
        }
    }
    respon = requests.post(url, headers=header, verify=False, data=json.dumps(scan_detail))
    return(respon.text)
    

if __name__ == '__main__':
    
    all_record = get_polices(header)['policies']
    Polices_Arr = []
    for i in all_record:
        Polices_Arr.append({ i['name']: i['id']})
        if(i['name']=='Base_Advance_Scan_Windows'):
            windows_base_temp_id = i['id']
            break
    #new_polices_id = copy_newpolicy(windows_base_temp_id)['id']
    #print(new_polices_id)
    print(get_polices_detail(windows_base_temp_id))
    print(assign_scan("ad629e16-03b6-8c1d-cef6-ef8c9dd3c658d24bd260ef5f9e66",windows_base_temp_id))
    #police_need = (get_polices_detail(new_polices_id))
    #print(police_need['credentials'])
    #new_police = changepassword("root","rootpassword",police_need)
    #change_offices(new_polices_id,new_police)

