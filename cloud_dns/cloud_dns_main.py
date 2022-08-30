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
# CLOUD_DDNS
# -------------------------------------------------------------------
import sys,os,logging,re,importlib
from json import loads,dumps
base_path = '/www/server/panel/'

sys.path.insert(0, base_path+"class/")
import public

class cloud_dns_main:

    def __init__(self):
        self.zone_file = base_path + 'plugin/cloud_dns/config/zone/{}.json'
        self.config_path = base_path + 'plugin/cloud_dns'

    def load_dns_module(self,dns_hosting):
        # 加载需要的dns模块
        sys.path.insert(0,base_path+"plugin/cloud_dns/module")
        dns_module = __import__('{}'.format(dns_hosting))
        return eval('dns_module.c_dns()')

    def list_hosting_domains(self,args):
        """
        dns_hosting cloudflare
        :param args:
        :return:
        """
        try:
            values = self.check_args(args)
            return self.load_dns_module(values['dns_hosting']).list_all_zones()
        except:
            return public.returnMsg(False,"Please check that the hosting information is correct")

    def list_zone_records(self,args):
        """
        dns_hosting cloudflare
        :param args:
        :return:
        """
        values = self.check_args(args)
        return self.load_dns_module(values['dns_hosting']).list_zone_records(values)

    def create_zone(self,args):
        self.clear_cache()
        values = self.check_args(args)
        return self.load_dns_module(values['dns_hosting']).create_zone(values)

    def remove_zone(self,args):
        self.clear_cache()
        values = self.check_args(args)
        return self.load_dns_module(values['dns_hosting']).remove_zone(values)

    def add_record(self,args):
        """
        record_name a.example.com
        zone example.com
        content 192.168.1.1
        type A
        ttl 120
        priority 10
        proxied true/false/null
        dns_hosting cloudflare
        :param args:
        :return:
        """
        values = self.check_args(args)
        self.clear_cache()
        return self.load_dns_module(values['dns_hosting']).add_record(values)
        # return self.load_dns_module(values['dns_hosting']).add_record(record_name=args.record_name,
        #                                                          zone=values['zone'],
        #                                                          type=args.type,
        #                                                          ttl=values['ttl'],
        #                                                          priority=values['priority'],
        #                                                          proxied=args.proxied,
        #                                                          content=values['content'])

    def remove_record(self,args):
        """
        zone
        record_id
        dns_hosting
        :param args:
        :return:
        """
        values = self.check_args(args)
        self.clear_cache()
        return self.load_dns_module(values['dns_hosting']).remove_record(values)

    def update_record(self,args):
        """
        record_name a.example.com
        zone example.com
        content 192.168.1.1
        type A
        ttl 120
        priority 10
        proxied true/false/null
        dns_hosting
        record_id
        :param args:
        :return:
        """
        values = self.check_args(args)
        self.clear_cache()
        return self.load_dns_module(values['dns_hosting']).update_record(values)
        # return self.load_dns_module(values['dns_hosting']).update_record(record_name=args.record_name,
        #                                                             zone=values['zone'],
        #                                                             type=args.type,
        #                                                             ttl=values['ttl'],
        #                                                             priority=values['priority'],
        #                                                             proxied=args.proxied,
        #                                                             content=values['content'],
        #                                                             id=args.record_id)

    def check_api(self,args):
        values = self.check_args(args)
        return self.load_dns_module(values['dns_hosting']).check_api(values)

    def set_auth_info(self,args):
        """
        dns_hosting: cloudflare 托管商
        value1
        value2
        zone
        :param args:
        :return:
        """
        values = self.check_args(args)
        config_file = self.config_path+'/dns_api.json'
        conf = public.readFile(config_file)
        if not conf:
            conf = [
    {
    "title": "Cloudflare",
    "name": "cloudflare",
    "help": "how to get token",
    "data": [
      {
        "key": "X-Auth-Key",
        "value": "",
        "name": "global_token"
      },
      {
        "key": "X-Auth-Email",
        "value": "",
        "name": "email"
      }
    ],
    "ps": "how to use"
  },
  {
    "title": "Alicloud",
    "name": "aliyun",
    "help": "how to get accesskey/secretkey",
    "data": [
      {
        "key": "SAVED_Ali_Key",
        "value": "",
        "name": "access_key"
      },
      {
        "key": "SAVED_Ali_Secret",
        "value": "",
        "name": "secret_key"
      }
    ],
    "ps": "how to use"
  },
  {
    "title": "DnsPod",
    "name": "dnspod",
    "help": "how to get token",
    "data": [
      {
        "key": "SAVED_DP_Id",
        "value": "",
        "name": "dp_id"
      },
      {
        "key": "SAVED_DP_Key",
        "value": "",
        "name": "dp_token"
      }
    ],
    "ps": "how to use"
  }
]
        else:
            conf = loads(conf)
        for i in conf:
            if i['name'] != values['dns_hosting']:
                continue
            for d in i['data']:
                if d['key'] == 'X-Auth-Key':
                    d['value'] = values['value1']
                if d['key'] == 'X-Auth-Email':
                    d['value'] = values['value2']
        public.writeFile(config_file,dumps(conf))
        return public.returnMsg(True,"Added successfully")

    def get_hosting_auth_info(self,args=None):
        """
        获取认证信息
        dns_hosting: cloudflare
        :param args:
        :return:
        """
        values = self.check_args(args)
        conf = self.get_hosting_auth()
        # return conf
        if not conf['status']:
            return conf
        for i in conf['msg']:
            if i['name'] != values['dns_hosting']:
                continue
            return i

    def get_hosting_auth(self):
        config_file = self.config_path+'/dns_api.json'
        conf = public.readFile(config_file)
        if not conf:
            return public.returnMsg(False,"Read dns_api.json error")
        conf = loads(conf)
        return public.returnMsg(True,conf)

    def get_hosting_name(self,args):
        auth_info = self.get_hosting_auth()
        if not auth_info['status']:
            return public.returnMsg(False,"Error reading configuration file!")
        tmp = []
        # secret = []
        for i in auth_info['msg']:
            # for d in i['data']:
                # if not d['value']:
                #     continue
                # secret.append(d['value'])
            tmp.append(i['name'])
        # if not secret:
        #     return public.returnMsg(False,"No hosting info set")
        return public.returnMsg(True,tmp)

    def clear_cache(self,args=None):
        if os.path.exists(self.config_path+'/cf_cache'):
            os.remove(self.config_path+'/cf_cache')
        if os.path.exists(self.config_path+'/cf_cache_account'):
            os.remove(self.config_path+'/cf_cache_account')
        if os.path.exists(self.config_path+'/dnspod_cache'):
            os.remove(self.config_path+'/dnspod_cache')
        if os.path.exists(self.config_path+'/dnspod_cache_line'):
            os.remove(self.config_path+'/dnspod_cache_line')
        if os.path.exists(self.config_path+'/aliyun_cache'):
            os.remove(self.config_path+'/aliyun_cache')
        return public.returnMsg(True,"The cleanup was successful.")


    def check_args(self,args):
        # 检查email格式
        rep_email = r"^\w+([.-]?\w+)*@.*"
        # 检查域名格式
        rep_domain = r"^(?=^.{3,255}$)[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62}(\.[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62})+$"
        rep_domain_point = "^(?=^.{3,255}$)[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+\.$"
        rep_host = "^[a-zA-Z0-9\_]+\-{0,1}\_{0,1}[a-zA-Z0-9\_]*$"
        # 检查IP格式
        rep_ip = r"^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$"
        rep_ipv6 = "^\s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*$"
        values = {}
        if hasattr(args,'zone'):
            if re.search(rep_domain, args.zone):
                values["zone"] = str(args.zone)
            else:
                return public.ReturnMsg(False, "Please check if the [zone] format is correct For example: example.com")
        if hasattr(args, "type"):
            rep = "(NS|A|CNAME|MX|TXT|AAAA|SRV|CAA|AFSDB|DS|HINFO|LOC|NAPTR|RP|SRV|PTR)"
            if re.search(rep, args.type):
                values["type"] = str(args.type)
            else:
                return public.ReturnMsg(False, "Please check if the parsing type format is correct.")
        if hasattr(args, "content"):
            try:
                if values["type"] == "A":
                    if re.search(rep_ip, args.content):
                        values["content"] = str(args.content)
                elif values["type"] == "NS":
                    if re.search(rep_ip, args.content):
                        values["content"] = str(args.content)
                    if re.search(rep_domain, args.content):
                        values["content"] = str(args.content)
                    if re.search(rep_domain_point, args.content):
                        values["content"] = str(args.content)
                    if re.search(rep_host, args.content):
                        values["content"] = str(args.content)
                elif values["type"] == "CNAME":
                    if re.search(rep_domain_point, args.content):
                        values["content"] = str(args.content)
                    if re.search(rep_domain, args.content):
                        values["content"] = str(args.content)
                # elif values["type"] == "DNAME":
                #     if re.search(rep_domain_point, args.content):
                #         values["content"] = str(args.content)
                #     if re.search(rep_domain, args.content):
                #         values["content"] = str(args.content) + "."
                elif values["type"] == "MX":
                    if re.search(rep_domain_point, args.content):
                        values["content"] = str(args.content)
                    if re.search(rep_domain, args.content):
                        values["content"] = str(args.content) + "."
                    if re.search(rep_ip, args.content):
                        values["content"] = str(args.content)+ "."
                elif values["type"] == "TXT":
                    values["content"] = str(args.content) if '"' == args.content[0] else str('"'+args.content+'"')
                elif values["type"] == "AAAA":
                    if re.search(rep_ipv6, args.content):
                        values["content"] = str(args.content)
                elif values["type"] in ["SRV","AFSDB","DS","HINFO","LOC","NAPTR","RP"]:
                    values["content"] = str(args.content)
                elif values["type"] == "PTR":
                    if re.search(rep_domain, args.content):
                        values["content"] = '{}.'.format(args.content)
                    elif re.search(rep_domain_point, args.content):
                        values["content"] = args.value
                elif values["type"] == "CAA":
                    values["flags"] = str(args.flags)
                    values["tag"] = str(args.tag)
                    values["ca_domain_name"] = str(args.ca_domain_name)
                    values["content"] = ''
                else:
                    values["content"] = args.content
                if "content" not in values: return public.ReturnMsg(False, "Please check if the record content format is correct")
            except:
                return public.ReturnMsg(False, "Please check if the record content format is correct")
        # if hasattr(args,'content'):
        #     if re.search(rep_ip, args.content):
        #         values["content"] = str(args.content)
        #     else:
        #         return public.ReturnMsg(False, "Please check if the [Content] format is correct For example: 1.1.1.1")
        if hasattr(args,'ttl'):
            try:
                values['ttl'] = int(args.ttl)
            except:
                values['ttl'] = 600
        if hasattr(args,'priority'):
            try:
                values['priority'] = int(args.priority)
            except:
                values['priority'] = 10
        if hasattr(args,'email'):
            if re.search(rep_email, args.email):
                values["email"] = str(args.email)
            else:
                return public.ReturnMsg(False, "Please check if the [Email] format is correct For example: test@example.com")
        if hasattr(args,'dns_hosting'):
            values['dns_hosting'] = args.dns_hosting
        if hasattr(args,'value1'):
            values['value1'] = args.value1
        if hasattr(args,'value2'):
            values['value2'] = args.value2
        if hasattr(args,'zone_id'):
            values['zone_id'] = args.zone_id
        if hasattr(args,'record_name'):
            values['record_name'] = args.record_name
        if hasattr(args,'proxied'):
            values['proxied'] = args.proxied
        if hasattr(args,'line_id'):
            values['line_id'] = args.line_id
        if hasattr(args,'status'):
            values['status'] = args.status
        if hasattr(args,'record_id'):
            values['record_id'] = args.record_id
        if hasattr(args,'account_id'):
            values['account_id'] = args.account_id
        if hasattr(args,'weight'):
            values['weight'] = args.weight
        if hasattr(args,'target'):
            values['target'] = args.target
        if hasattr(args,'service'):
            values['service'] = args.service
        if hasattr(args,'proto'):
            values['proto'] = args.proto
        if hasattr(args,'port'):
            values['port'] = args.port

        for k in values:
            try:
                values[k] = public.xssencode2(values[k])
            except:
                pass
        return values
