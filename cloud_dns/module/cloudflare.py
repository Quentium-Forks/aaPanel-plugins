#!/usr/bin/python
#coding: utf-8
# -------------------------------------------------------------------
# 宝塔Linux面板
# -------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# -------------------------------------------------------------------
# Author: zhwen <zhw@bt.cn>
# -------------------------------------------------------------------

# -------------------------------------------------------------------
# cloudflare DDNS
# -------------------------------------------------------------------
import sys, time
base_path = '/www/server/panel/'
sys.path.insert(0, base_path+"class/")
import public
import requests
from json import loads,dumps

class c_dns:

    def __init__(self):
        self.endpoints = 'https://api.cloudflare.com/client/v4/'
        self.config_file = base_path+'plugin/cloud_dns/dns_api.json'
        self.cache_file = '{}plugin/cloud_dns/cf_cache'.format(base_path)
        self.auth_conf = self._get_auth_config()
        self.values = None

    def _get_auth_config(self):
        """
        获取认证配置信息
    {
    "title": "Cloudflare",
    "name": "cloudflare",
    "help": "how to get token",
    "data": [
      {
        "key": "X-Auth-Key",
        "value": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "name": "global_token"
      },
      {
        "key": "X-Auth-Email",
        "value": "aa@aa.com",
        "name": "email"
      }
    ],
    "ps": "how to use"
  }
        :return:
        """
        conf = public.readFile(self.config_file)
        if not conf:
            return {}
        try:
            for auth_info in loads(conf):
                if 'cloudflare' == auth_info['name']:
                    return auth_info
        except:pass
        return {}

    def get_headers(self):
        token = ''
        email = ''
        for i in self.auth_conf['data']:
            if 'X-Auth-Key' == i['key']:
                token = i['value']
            else:
                email = i['value']
        return {"X-Auth-Email": email, "X-Auth-Key": token,"Content-Type": "application/json"}

    # 认证状态

    # 服务状态

    # 设置服务状态

    #获取用户信息
    def list_account_info(self):
        cache = public.readFile(self.cache_file+'_account')
        if cache:
            cache = loads(cache)
            if time.time() - cache['time'] < 86400 and cache['result']:
                return cache['result']
        headers = self.get_headers()
        url = self.endpoints + 'accounts'
        resp = requests.get(url, headers=headers).json()['result']
        public.writeFile(self.cache_file+'_account',dumps({'time':time.time(),'result':resp}))
        return resp

    #获取所有托管的域名
    def list_all_zones(self):
        account_info = self.list_account_info()
        cache = public.readFile(self.cache_file)
        if cache:
            cache = loads(cache)
            if time.time() - cache['time'] < 86400 and cache['result']:
                return public.returnMsg(True,{'resp':self.__build_zones_info(cache['result']),'account_info':account_info})
        headers = self.get_headers()
        url = self.endpoints+'zones/?per_page=100'
        resp = requests.get(url, headers=headers).json()['result']
        public.writeFile(self.cache_file,dumps({'time':time.time(),'result':resp}))
        resp = self.__build_zones_info(resp)
        return public.returnMsg(True, {'resp':resp,'account_info':account_info})

    def __build_zones_info(self,data):
        tmp = []
        for d in range(len(data)):
            tmp.append({
                'zone_id': data[d]['id'],
                'domain':data[d]['name'],
                'ns': data[d]['name_servers'],
                'status':"enable" if data[d]['status'] == "active" else "disable"
            })
        return tmp

    def list_zone_records(self,values):
        """
        zone_id 域名的ID
        :param values:
        :return:
        """
        headers = self.get_headers()
        # zone_id = self.get_zone_id(values['zone'])
        url = self.endpoints + 'zones/{}/dns_records?per_page=5000'.format(values['zone_id'])
        resp = requests.get(url, headers=headers).json()['result']
        # return resp
        return public.returnMsg(True,self.__build_records(resp))

    def __build_records(self,data):
        tmp = []
        for d in range(len(data)):
            tmp.append({'id':data[d]['id'],                 #记录ID
                        'ttl':data[d]['ttl'],
                        'records':data[d]['name'],
                        'value': data[d]['content'],
                        'type':data[d]['type'],
                        'priority': 0 if 'priority' not in data[d] else data[d]['priority'],    #MX记录优先级
                        'proxiable': data[d]['proxiable'],  #可代理的记录（公网IP可代理）
                        'proxied': data[d]['proxied'],      #代理状态
                        })
        return tmp

    # 获取zoneid
    def get_zone_id(self,zone):
        # 获取域名ID
        zones = self.list_all_zones()
        for i in zones:
            if i['name'] == zone:
                return i['id']

    def _check_priority(self):
        try:
            self.values['priority'] = int(self.values['priority'])
        except:
            self.values['priority'] = 10

    def _check_ttl(self):
        try:
            self.values['ttl'] = int(self.values['ttl'])
        except:
            self.values['ttl'] = 1

    def _check_proxied(self):
        if self.values['proxied'] == 'false':
            self.values['proxied'] = False
        else:
            self.values['proxied'] = True

    def _check_record_name(self):
        if self.values['zone'] in self.values['record_name']:
            self.values['record_name'] = self.values['record_name'].replace('.'+self.values['zone'],'')

    def _check_values(self):
        self._check_ttl()
        self._check_priority()
        self._check_proxied()
        self._check_record_name()

    def _make_srv_param(self,values):
        return

    def _make_data(self):
        values = self.values
        if values['type'] == "CAA":
            data = {"flags":values['flags'],
                    "tag":values["tag"],
                    "value":values['ca_domain_name']
                    }
        elif values['type'] == 'SRV':
            data = {"name":values['name'],
                    "port":values["port"],
                    "priority":values["priority"],
                    "proto":values["proto"],
                    "service":values["service"],
                    "target":values["target"],
                    "weight":values["weight"]
                    }
        else:
            data = {}
        return data

    def _make_content(self):
        if self.values['type'] == 'SRV':
            self.values['content'] = "{} {} {} {}".format(
                self.values['priority'],
                self.values['weight'],
                self.values['port'],
                self.values['target']
            )

    def _make_record_name(self):
        if self.values['type'] == 'SRV':
            self.values['name'] = self.values['record_name']
            self.values['record_name'] = "{}{}{}{}".format(
                self.values['service'],
                self.values['proto'],
                self.values['record_name'],
                self.values['zone'])

    def _make_url_data(self):
        self._make_record_name()
        self._make_content()
        values = self.values
        url_data = {"type":values['type'],
                    "name":self.values['record_name'],
                    "content":self.values['content'],
                    "ttl":int(values['ttl']),
                    "priority":int(values['priority']),
                    "proxied":values['proxied'],
                    "data":self._make_data()}
        return url_data

    # 添加ddns记录
    def add_record(self, values):
        auth_conf = self._get_auth_config()
        self.values = values
        # 检查传入参数
        self._check_values()
        if not auth_conf:
            return {'status': False, 'msg': 'No authentication information for cloudflare found'}
        url_data = self._make_url_data()
        url_headers = self.get_headers()
        url = self.endpoints + "zones/{}/dns_records".format(values['zone_id'])
        resp = requests.post(url, headers=url_headers,data=dumps(url_data))
        if resp.json()['success']:
            return {'status': True, 'msg': 'Added record successfully'}
        return {'status': False, 'msg': 'Failed to add record：{}'.format(resp.json()['errors'])}

    # 更新某一条ddns记录
    def update_record(self, values):
        """
        :param record_name record.expamel.com:
        :param content:
        :param zone:
        :param type:
        :param ttl:
        :param priority:
        :param proxied bool:
        :return:
        """
        auth_conf = self._get_auth_config()
        if not auth_conf:
            return {'status':False,'msg':'CloudFlare API authentication information is not set'}
        if not values['priority'] or not isinstance(values['priority'],int):
            values['priority'] = 10
        if not values['proxied']:
            values['proxied'] = False
        else:
            if values['proxied'] == 'false':
                values['proxied'] = False
            else:
                values['proxied'] = True
        if not values['ttl'] or not isinstance(values['proxied'],int):
            values['ttl'] = 1
        url_data = {"type":values['type'],"name":values['record_name'],"content":values['content'],"ttl":int(values['ttl']),
                    "priority":int(values['priority']),"proxied":values['proxied']}
        url_headers = self.get_headers()
        url = self.endpoints + "zones/{}/dns_records/{}".format(values['zone_id'],values['record_id'])
        resp = requests.put(url, headers=url_headers,data=dumps(url_data))
        if resp.json()['success']:
            # self._set_ddns_to_conf(values['zone'],values['id'],values['record_name'],values['content'],values['ttl'],
            #                        values['priority'],values['proxied'],values['type'],act='update')
            return {'status':True,'msg':'Successfully updated the record'}
        return {'status': False, 'msg': 'Failed to update record：{}'.format(resp.json()['errors'])}

    def remove_record(self,values):
        """
        :param id:
        :param zone:
        :return:
        """
        auth_conf = self._get_auth_config()
        if not auth_conf:
            return False
        url_headers = self.get_headers()
        url = self.endpoints + "zones/{}/dns_records/{}".format(values['zone_id'],values['record_id'])
        resp = requests.delete(url, headers=url_headers)
        if resp.json()['success'] or 'Record does not exist' in resp.json()['errors'][0]['message']:
            # self._set_ddns_to_conf(values['zone'],values['id'],act='delete')
            return {'status':True,'msg':'Delete record successfully'}
        return {'status': False, 'msg': 'Failed to delete record：{}'.format(resp.json()['errors'])}

    def check_api(self,values):
        headers = {"X-Auth-Email": values['value2'], "X-Auth-Key": values['value1'],"Content-Type": "application/json"}
        url = self.endpoints+'zones'
        resp = requests.get(url, headers=headers).json()
        if resp['success'] == True:
            return public.returnMsg(True, 'Connection succeeded')
        return public.returnMsg(False, 'Connection failed')

    def create_zone(self,values):
        auth_conf = self._get_auth_config()
        if not auth_conf:
            return False
        url_headers = self.get_headers()
        url = self.endpoints + "zones"
        data = {"name":values['zone'],
                "account":{"id":values['account_id']}
                }
        resp = requests.post(url, headers=url_headers, data=dumps(data)).json()
        if resp['success'] == True:
            return public.returnMsg(True, 'Create zone successfully')
        return public.returnMsg(False, 'Create zone failed')

    def remove_zone(self,values):
        auth_conf = self._get_auth_config()
        if not auth_conf:
            return False
        url_headers = self.get_headers()
        url = self.endpoints + "zones/{}".format(values['zone_id'])
        resp = requests.delete(url, headers=url_headers).json()
        if resp['success'] == True:
            return public.returnMsg(True, 'Remove zone successfully')
        return public.returnMsg(False, 'Remove zone failed')