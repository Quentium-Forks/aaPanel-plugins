#coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Windows面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2020 宝塔软件(http://www.bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: zhw <zhw@bt.cn>
# +-------------------------------------------------------------------
import os, sys,datetime
panel_path = os.getenv('BT_PANEL')
if not panel_path: panel_path = '/www/server/panel'
os.chdir(panel_path)
sys.path.insert(0,panel_path + "/class/")
import public,json,time,base64,hmac,requests,random
from hashlib import sha1

class c_dns:

    def __init__(self):
        self.access_key = None
        self.secret_key = None
        self.config_file = panel_path + '/plugin/cloud_dns/dns_api.json'
        self.cache_file = '{}/plugin/cloud_dns/aliyun_cache'.format(panel_path)
        self.endpoints = "http://alidns.aliyuncs.com/"
        self._get_auth_config()
        self.random_int = random.randint(11111111111111, 99999999999999)
        self.values = None

    def _get_auth_config(self):
        conf = public.readFile(self.config_file)
        if not conf:
            return {}
        try:
            for auth_info in json.loads(conf):
                if 'aliyun' == auth_info['name']:
                    for d in auth_info['data']:
                        if d['name'] == 'access_key':
                            self.access_key = d['value']
                        if d['name'] == 'secret_key':
                            self.secret_key = d['value']
                    return auth_info
        except:pass
        return {}

    #签名
    def sign(self, accessKeySecret, parameters):
        def percent_encode(encodeStr):
            encodeStr = str(encodeStr)
          
            import urllib.request
            res = urllib.request.quote(encodeStr, '')
       
            res = res.replace('+', '%20')
            res = res.replace('*', '%2A')
            res = res.replace('%7E', '~')
            return res

        sortedParameters = sorted(parameters.items(), key=lambda parameters: parameters[0])
        canonicalizedQueryString = ''
        for (k, v) in sortedParameters:
            canonicalizedQueryString += '&' + percent_encode(k) + '=' + percent_encode(v)
        stringToSign = 'GET&%2F&' + percent_encode(canonicalizedQueryString[1:])
        if sys.version_info[0] == 2:
            h = hmac.new(accessKeySecret + "&", stringToSign, sha1)
        else:
            h = hmac.new(bytes(accessKeySecret + "&", encoding="utf8"), stringToSign.encode('utf8'), sha1)
        signature = base64.encodestring(h.digest()).strip()
        return signature

    def list_all_zones(self):
        cache = public.readFile(self.cache_file)
        if cache:
            cache = json.loads(cache)
            if time.time() - cache['time'] < 86400 and cache['result']:
                return public.returnMsg(True,self.__build_zones_info(cache['result']))
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "DescribeDomains", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1", "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "AccessKeyId": self.access_key,"SignatureNonce": str(self.random_int)
        }

        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()['Domains']['Domain']
        public.writeFile(self.cache_file, json.dumps({'time': time.time(), 'result': resp}))
        return public.returnMsg(True,self.__build_zones_info(resp))

    def __build_zones_info(self,data):
        tmp = []
        for d in range(len(data)):
            tmp.append({
                'zone_id': data[d]['DomainId'],
                'domain':data[d]['DomainName'],
                'ns': data[d]['DnsServers']['DnsServer'],
                'status': 'enable'
            })
        return tmp

    def check_api(self,values):
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "DescribeDomains", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1", "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "AccessKeyId": values['value1'],"SignatureNonce": str(self.random_int)
        }

        Signature = self.sign(values['value2'], paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()
        if "TotalCount" in resp:
            return public.returnMsg(True, 'Connection succeeded')
        return public.returnMsg(False, 'Connection failed')

    def create_zone(self,values):
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "AddDomain", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1", "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "AccessKeyId": self.access_key,"SignatureNonce": str(self.random_int),
            "DomainName":values['zone']
        }

        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()
        if 'Code' in resp:
            if resp['Code'] == "InvalidDomainName.Unregistered":
                return public.returnMsg(False,"The domain [{}] has not been registered yet, please buy it before adding it".format(values['zone']))
            if resp['Code'] == "DomainAddedByOthers":
                return public.returnMsg(False,"The domain [{}] has not been add by another user!".format(values['zone']))
            if resp['Code'] == "InvalidDomainName.Format":
                return public.returnMsg(False,"The domain [{}] format error!".format(values['zone']))
        return public.returnMsg(True, 'Create zone successfully')

    def remove_zone(self,values):
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "DeleteDomain", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1", "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "AccessKeyId": self.access_key,"SignatureNonce": str(self.random_int),
            "DomainName":values['zone']
        }

        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()
        if 'Code' in resp and resp['Code'] == "InvalidDomainName.NoExist":
            return public.returnMsg(False,"The domain [{}] dose not exist!".format(values['zone']))
        return public.returnMsg(True,"Remove zone successfully")

    def list_zone_records(self,values):
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "DescribeDomainRecords", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1",
            "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "AccessKeyId": self.access_key, "SignatureNonce": str(self.random_int),
            "DomainName": values['zone'],"PageSize":"500"
        }

        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()
        if 'Code' in resp and resp['Code']== "InvalidDomainName.NoExist":
            return public.returnMsg(False,"The domain [{}] dose not exist!".format(values['zone']))
        records = self.__build_records(resp['DomainRecords']['Record'])
        line_ids = self.get_line_ids()
        return public.returnMsg(True, {'line_ids': line_ids,'records':records})

    def __build_records(self,data):
        tmp = []
        for d in range(len(data)):
            tmp.append({'id':data[d]['RecordId'],
                        'ttl':data[d]['TTL'],
                        'status':True if data[d]['Status'] == 'ENABLE' else False,
                        'record_name':data[d]['RR'],
                        'value': data[d]['Value'],
                        'line':data[d]['Line'],
                        'type':data[d]['Type'],
                        'priority':0 if 'Priority' not in data[d] else data[d]['Priority']
                        })
        return tmp

    def get_line_ids(self):
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "DescribeSupportLines", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1",
            "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "AccessKeyId": self.access_key, "SignatureNonce": str(self.random_int)
        }

        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()['RecordLines']['RecordLine']
        return resp

    def _make_content(self):
        if self.values['type'] == 'SRV':
            self.values['content'] = "{} {} {} {}".format(
                self.values['priority'],
                self.values['weight'],
                self.values['port'],
                self.values['target']
            )
        if self.values['type'] == 'CAA':
            self.values['content'] = '{} {} "{}"'.format(
                self.values['flags'],
                self.values['tag'],
                self.values['ca_domain_name'])

    def _make_record_name(self):
        if self.values['type'] == 'SRV':
            self.values['record_name'] = "{}{}".format(
                self.values['service'],
                self.values['proto']
            )

    def add_record(self,values):
        self.values = values
        self._make_record_name()
        self._make_content()
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "AddDomainRecord", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1", "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "SignatureNonce": str(self.random_int), "AccessKeyId": self.access_key,
            "DomainName": values['zone'],
            "RR": self.values['record_name'],
            "Type": values['type'],
            "TTL": values['ttl'],
            "Line": values['line_id'],
            "Value": self.values['content']
            # "Status": "ENABLE" if 'enable' == values['status'] else "DISABLE"
        }
        # return paramsdata
        if str(values['priority']) != '0':
            paramsdata['Priority'] = values['priority']
        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()
        if 'Code' in resp:
            if resp['Code'] == 'IncorrectDomainUser' or resp['Code'] == 'InvalidDomainName.NoExist':
                return public.returnMsg(False,"这个阿里云账户下面不存在这个域名，添加解析失败")
            elif resp['Code'] == 'InvalidAccessKeyId.NotFound' or resp['Code'] == 'SignatureDoesNotMatch':
                return public.returnMsg(False,"API密钥错误，添加解析失败")
            else:
                return public.returnMsg(False,resp['Message'])
        return public.returnMsg(True,"Add record successfully")

    def remove_record(self,values):
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "DeleteDomainRecord", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1", "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "SignatureNonce": str(self.random_int), "AccessKeyId": self.access_key,
            "RecordId": values['record_id']
        }
        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()
        if 'Code' in resp:
            if resp['Code'] == 'IncorrectDomainUser' or resp['Code'] == 'InvalidDomainName.NoExist':
                return public.returnMsg(False,"这个阿里云账户下面不存在这个域名，添加解析失败")
            elif resp['Code'] == 'InvalidAccessKeyId.NotFound' or resp['Code'] == 'SignatureDoesNotMatch':
                return public.returnMsg(False,"API密钥错误，添加解析失败")
            else:
                return public.returnMsg(False,resp['Message'])
        return public.returnMsg(True,"Remove record successfully")

    def update_record(self,values):
        now = datetime.datetime.utcnow()
        otherStyleTime = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        paramsdata = {
            "Action": "UpdateDomainRecord", "Format": "json", "Version": "2015-01-09", "SignatureMethod": "HMAC-SHA1", "Timestamp": otherStyleTime,
            "SignatureVersion": "1.0", "SignatureNonce": str(self.random_int), "AccessKeyId": self.access_key,
            "RR": values['record_name'],
            "Type": values['type'],
            "TTL": values['ttl'],
            "Line": values['line_id'],
            "Value": values['content'],
            "RecordId":values['record_id'],
            "DomainName":values['zone']
            # "Status": "ENABLE" if 'enable' == values['status'] else "DISABLE"
        }
        if str(values['priority']) != '0':
            paramsdata['Priority'] = values['priority']
        Signature = self.sign(self.secret_key, paramsdata)
        paramsdata['Signature'] = Signature
        resp = requests.get(url=self.endpoints, params=paramsdata).json()
        if 'Code' in resp:
            if resp['Code'] == 'IncorrectDomainUser' or resp['Code'] == 'InvalidDomainName.NoExist':
                return public.returnMsg(False,"这个阿里云账户下面不存在这个域名，添加解析失败")
            elif resp['Code'] == 'InvalidAccessKeyId.NotFound' or resp['Code'] == 'SignatureDoesNotMatch':
                return public.returnMsg(False,"API密钥错误，添加解析失败")
            else:
                return public.returnMsg(False,resp['Message'])
        return public.returnMsg(True,"Update record successfully")