#coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Windows面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2020 宝塔软件(http://www.bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: zhw <zhw@bt.cn>
# +-------------------------------------------------------------------
import os, sys,requests
panel_path = os.getenv('BT_PANEL')
if not panel_path: panel_path = '/www/server/panel'
os.chdir(panel_path)
sys.path.insert(0,panel_path + "/class/")
import public,json
import time,html

class c_dns:

    def __init__(self):
        self.endpoints = 'https://dnsapi.cn/'
        self.config_file = panel_path + '/plugin/cloud_dns/dns_api.json'
        self.cache_file = '{}/plugin/cloud_dns/dnspod_cache'.format(panel_path)
        self.HTTP_TIMEOUT = 65  # seconds
        self.login_token = None
        self._get_auth_config()

    def _get_auth_config(self):
        conf = public.readFile(self.config_file)
        if not conf:
            return {}
        try:
            for auth_info in json.loads(conf):
                if 'dnspod' == auth_info['name']:
                    dp_id = dp_token = ''
                    for d in auth_info['data']:
                        if d['name'] == 'dp_id':
                            dp_id = d['value']
                        if d['name'] == 'dp_token':
                            dp_token = d['value']
                    self.login_token = "{0},{1}".format(dp_id, dp_token)
                    return auth_info
        except:pass
        return {}

    def list_all_zones(self):
        """
        获取dnspod托管的所有域名
        :return:
        """
        cache = public.readFile(self.cache_file)
        if cache:
            cache = json.loads(cache)
            if time.time() - cache['time'] < 86400 and cache['result']:
                return public.returnMsg(True,self.__build_zones_info(cache['result']))
        url = self.endpoints + 'Domain.List'
        data = {"login_token":self.login_token}
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == "1":
            public.writeFile(self.cache_file, json.dumps({'time': time.time(), 'result': resp["domains"]}))
            return public.returnMsg(True,self.__build_zones_info(resp['domains']))

    def __build_zones_info(self,data):
        tmp = []
        for d in range(len(data)):
            tmp.append({
                'zone_id': data[d]['id'],
                'domain':data[d]['name'],
                'ns': data[d]['grade_ns'],
                'status': data[d]['status']
            })
        return tmp

    def check_api(self,values):
        url = self.endpoints + 'Domain.List'
        data = {"login_token":"{},{}".format(values['value2'],values['value1'])}
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == "1":
            return public.returnMsg(True, 'Connection succeeded')
        return public.returnMsg(False, 'Connection failed')

    def create_zone(self,values):
        url = self.endpoints + 'Domain.Create'
        data = {"login_token": self.login_token,
                "domain":values['zone']}
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == '1':
            return public.returnMsg(True,'Create zone successfully')
        return public.returnMsg(False,'Create zone failed')

    def remove_zone(self,values):
        url = self.endpoints + 'Domain.Remove'
        data = {"login_token": self.login_token,
                "domain_id":values['zone_id']}
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == '1':
            return public.returnMsg(True,'Delete zone successfully')
        return public.returnMsg(False,'Delete zone failed')

    def list_zone_records(self,values):
        url = self.endpoints + 'Record.List'
        data = {"login_token": self.login_token,
                "domain_id":values['zone_id']}
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        # 获取可用线路的ID
        #返回值 {“默认”：0，“百度”：“90=0”...}
        line_ids = self.get_line_ids(values)
        if resp['status']['code'] == '1':
            records = self.__build_records(resp['records'])
            return public.returnMsg(True,{'line_ids': line_ids,'records':records})
        return public.returnMsg(False,'list record failed')

    def __build_records(self,data):
        tmp = []
        for d in range(len(data)):
            tmp.append({'id':data[d]['id'],
                        'ttl':data[d]['ttl'],
                        'status':True if data[d]['status'] == 'enable' else False,
                        'record_name':data[d]['name'],
                        'value': data[d]['value'],
                        'line':data[d]['line'],
                        'type':data[d]['type'],
                        'priority':data[d]['mx']
                        })
        return tmp

    def get_line_ids(self,values):
        """
        获取dnspod线路
        :param values:
        :return:
        """
        cache = public.readFile(self.cache_file+'_line')
        if cache:
            cache = json.loads(cache)
            if time.time() - cache['time'] < 86400 and cache['result']:
                return cache['result']
        url = self.endpoints + 'Record.Line'
        data = {"login_token": self.login_token,
                "domain_id":values['zone_id']}
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == '1':
            public.writeFile(self.cache_file+'_line',json.dumps({'time':time.time(),'result':resp['line_ids']}))
            return resp['line_ids']
        return public.returnMsg(False,'list line id failed')

    def add_record(self,values):
        url = self.endpoints + 'Record.Create'
        data = {"login_token": self.login_token,
                "domain_id":values['zone_id'],
                "sub_domain": values['record_name'],
                'record_type': values['type'],
                'record_line_id':values['line_id'],
                'value':values['content'],
                'mx':values['priority'],
                'ttl':values['ttl'],
                'status':values['status'] #enable/disable
                }
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == '1':
            # return resp
            return public.returnMsg(True,'Add record successfully')
        # return resp
        return public.returnMsg(False,'Add record failed')

    def remove_record(self,values):
        url = self.endpoints + 'Record.Remove'
        data = {"login_token": self.login_token,
                "domain_id":values['zone_id'],
                "record_id":values['record_id']
                }
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == '1':
            # return resp
            return public.returnMsg(True,'Delete record successfully')
        # return resp
        return public.returnMsg(False,'Delete record failed')

    def update_record(self,values):
        url = self.endpoints + 'Record.Modify'
        data = {"login_token": self.login_token,
                "record_id": values['record_id'],
                "domain_id":values['zone_id'],
                "sub_domain": values['record_name'],
                'record_type': values['type'],
                'record_line_id':values['line_id'],
                'value':values['content'],
                'mx':values['priority'],
                'ttl':values['ttl'],
                'status':values['status'] #enable/disable
                }
        resp = requests.post(url, data=data, timeout=self.HTTP_TIMEOUT).json()
        if resp['status']['code'] == '1':
            # return resp
            return public.returnMsg(True,'Update record successfully')
        # return resp
        return public.returnMsg(False,'Update record failed')