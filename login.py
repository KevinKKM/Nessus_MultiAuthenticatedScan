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
    polices['credentials'] = new_credential['credentials']
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
    
def change_offices(id,polices):
    result = ''
    url = "https://192.168.232.139:8834/policies/9"
    #url = "https://192.168.232.139:8834/policies"
    header = {'X-ApiKeys': 'accessKey={accesskey};secretKey={secretkey}'.format(accesskey=AccessKey, secretkey=SecretKey),
          'Content-type': 'application/json',
          'Accept': 'text/plain'}
    make_head = {'credentials': {'edit': {'10': {'username': 'userA', 'password': 'passwordA', 'domain': 'test.local', 'auth_method': 'Password'}}}, 'settings': {'patch_audit_over_rexec': 'no', 'patch_audit_over_rsh': 'no', 'ssh_client_banner': 'OpenSSH_5.0', 'description': 'just a test', 'http_login_auth_regex_nocase': 'no', 'http_login_method': 'POST', 'ssh_port': '22', 'report_verbosity': 'Normal', 'enable_admin_shares': 'no', 'http_login_invert_auth_regex': 'no', 'dont_use_ntlmv1': 'yes', 'additional_snmp_port3': '161', 'allow_post_scan_editing': 'yes', 'display_unreachable_hosts': 'no', 'assessment_mode': 'Default', 'start_remote_registry': 'yes', 'http_login_auth_regex_on_headers': 'no', 'silent_dependencies': 'yes', 'ssh_known_hosts': '', 'patch_audit_over_telnet': 'no', 'http_login_max_redir': '0', 'http_reauth_delay': '0', 'advanced_mode': 'Default', 'attempt_least_privilege': 'no', 'reverse_lookup': 'no', 'never_send_win_creds_in_the_clear': 'yes', 'additional_snmp_port2': '161', 'report_superseded_patches': 'yes', 'additional_snmp_port1': '161', 'snmp_port': '161', 'name': 'Copy of testpolices'}, 'uuid': 'd16c51fa-597f-67a8-9add-74d5ab066b49a918400c42a035f7'}
    respon = requests.put(url, headers=header, verify=False, data=json.dumps(make_head))
    #print(make_head)
    print(respon.text)
    

if __name__ == '__main__':
    first_record_id = get_polices(header)['policies'][1]['id'] #obtain the first record
    polices = (get_polices_detail(first_record_id))
    print(polices)
    new_police = changepassword("userA","passwordA",polices)
    change_offices(first_record_id,new_police)

