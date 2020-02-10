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
    new_credential = {'credentials': {'edit': {'7': {'username': '%s'%uname, 'password': '%s'%pwd, 'domain': 'test.local', 'auth_method': 'Password'}}}}
    polices['credentials'] = new_credential
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
    url = "https://192.168.232.139:8834/policies/%d/copy"%d

    respon = requests.post(url, headers=header, verify=False)
    if respon.status_code == 200:
        result = json.loads(respon.text)
    return result
    
    
if __name__ == '__main__':
    first_record_id = get_polices(header)['policies'][1]['id'] #obtain the first record
    polices = (get_polices_detail(first_record_id))
    new_police = changepassword("userA","passwordA",polices)

