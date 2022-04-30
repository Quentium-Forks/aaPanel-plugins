#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: zhwem <zhw@bt.cn>
# +-------------------------------------------------------------------

#+--------------------------------------------------------------------
#|   宝塔fail2ban管理器 cloudflare 拦截设置
#+--------------------------------------------------------------------

import public,requests
import re,json

class set_cdn_defence:
    _set_up_path = "/www/server/panel/plugin/fail2ban"
    _cdn_config = _set_up_path + "/cdn_config.json"
    endpoints = 'https://api.cloudflare.com/client/v4/'

    def __init__(self):
        self.cfuser,self.cftoken =self.get_cdn_conf()

    def get_cdn_conf(self):
        conf = public.readFile(self._cdn_config)
        if not conf:
            return False,False
        try:
            conf = json.loads(conf)
            return conf['cloudflare']['user'],conf['cloudflare']['token']
        except:
            return False, False

    def get_headers(self,cfuser,cftoken):
        headers = {"X-Auth-Email": cfuser, "X-Auth-Key": cftoken,
                   "Content-Type": "application/json"}
        return headers

    def build_cf_action(self, data):
        """
        zone_id 你的需要保护的域名id
        cdn_provide cdn提供商
        :param:
        :return:
        """
        str="""
[Definition]
actionstart =
actionstop =
actioncheck =
actionban = curl -s -X POST "https://api.cloudflare.com/client/v4/zones/<cfzoneid>/firewall/access_rules/rules" \
                             -H "X-Auth-Email: <cfuser>" \
                             -H "X-Auth-Key: <cftoken>" \
                             -H "Content-Type: application/json" \
                             --data '{"mode":"block","configuration":{"target":"ip","value":"<ip>"},"notes":"CC Attack"}'
actionunban = curl -s -X DELETE "https://api.cloudflare.com/client/v4/zones/<cfzoneid>/firewall/access_rules/rules/$( \
                               curl -s -X GET "https://api.cloudflare.com/client/v4/zones/<cfzoneid>/firewall/access_rules/rules?page=1&per_page=1&mode=block&configuration.target=ip&configuration.value=<ip>&match=all" \
                               -H "X-Auth-Email: <cfuser>" \
                               -H "X-Auth-Key: <cftoken>" \
                               -H "Content-Type: application/json" | awk -F "[,:}]" '{for(i=1;i<=NF;i++){if($i~/'id'\042/){print $(i+1);}}}' | tr -d '"' | sed -e 's/^[ \t]*//' | head -n 1)" \
                      -H "X-Auth-Email: <cfuser>" \
                      -H "X-Auth-Key: <cftoken>" \
                      -H "Content-Type: application/json"
[Init]
name = default
cfuser = %s
cftoken = %s
cfzoneid = %s
    """ % (self.cfuser,self.cftoken,data['zone_id'])
        public.writeFile('/etc/fail2ban/action.d/{}.conf'.format(data['zone_id']),str)

    def set_webserver_log(self,data):
        webserver = public.get_webserver()
        if webserver == 'nginx':
            self.set_nginx_log(data)
        elif webserver == 'apache':
            self.set_apache_log(data)
        else:
            # OLS默认已经设置了XFF头
            pass

    def set_apache_log(self,data):
#         conf = public.readFile('/www/server/apache/conf/httpd.conf')
#         if not conf:
#             return public.returnMsg(False,'Apache conf file not found!')
#         str = """
# <IfModule log_config_module>
#     #
#     # The following directives define some format nicknames for use with
#     # a CustomLog directive (see below).
#     #
#     LogFormat '%{X-Forwarded-For}i %h %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i"' combined
#     LogFormat '%{X-Forwarded-For}i %h %l %u %t "%r" %>s %b"' common
#
#     <IfModule logio_module>
#       # You need to enable mod_logio.c to use %I and %O
#       LogFormat '"%h %a %l %u %t "%r" %>s %b "%{Referer}i" "%{User-Agent}i" %I %O"' combinedio
#     </IfModule>"""
#         if 'LogFormat "%{X-Forwarded-For}i' in conf:
#             return True
#         conf = re.sub('<IfModule log_config_module>(.|\n)+LogFormat.*\n\s*</IfModule>',str,conf)
#         public.writeFile('/www/server/apache/conf/httpd.conf',conf)
#         public.ServiceReload()
        try:
            get_tmp.log_format_name='f2bcdnformat'
            get_tmp.log_format= json.dumps(["%{X-Forwarded-For}i","%h","%l","%u","%t","%r","%>s","%b","%{Referer}i","%{User-agent}i"])
            import apache
            n = apache.apache()
            get_tmp.act = data['type']
            ap_conf = public.readFile('/www/server/apache/conf/httpd.conf')
            if ap_conf and 'f2bcdnformat' not in ap_conf:
                n.add_httpd_access_log_format(get_tmp)
            # 将格式设置到网站下
            vhost_conf = public.readFile('/www/server/panel/vhost/apache/{}.conf'.format(data['sitename']))

            if vhost_conf and 'f2bcdnformat' not in vhost_conf:
                get_tmp.sites = json.dumps([data['sitename']])
                n.set_httpd_format_log_to_website(get_tmp)
        except:
            public.writeFile(self._set_up_path+'/cdn_error.log',str(public.get_error_info()))

    def set_nginx_log(self,data):
        try:
            get_tmp.log_format_name='f2bcdnformat'
            get_tmp.log_format= json.dumps(["$http_x_forwarded_for","$remote_addr","-","[$time_local]","$request","$status","$body_bytes_sent","$http_referer","$http_user_agent"])
            import nginx
            n = nginx.nginx()
            get_tmp.act = data['type']
            ng_conf = public.readFile('/www/server/nginx/conf/nginx.conf')
            if ng_conf and 'f2bcdnformat' not in ng_conf:
                n.add_nginx_access_log_format(get_tmp)
            # 将格式设置到网站下
            vhost_conf = public.readFile('/www/server/panel/vhost/nginx/{}.conf'.format(data['sitename']))

            if vhost_conf and 'f2bcdnformat' not in vhost_conf:
                get_tmp.sites = json.dumps([data['sitename']])
                n.set_format_log_to_website(get_tmp)
        except:
            public.writeFile(self._set_up_path+'/cdn_error.log',str(public.get_error_info()))

    def check_auth_info(self,data):
        url_headers = self.get_headers(data['user'],data['token'])
        url = self.endpoints + "user"
        resp = requests.get(url, headers=url_headers)
        return resp.json()['success']

    def check_conf(self):
        '''
        检查配置是否已经设置成功，不成功则回滚并提示错误信息
        :return:
        '''
        pass

    def main(self,data):
        self.build_cf_action(data)
        self.set_webserver_log(data)
        return public.returnMsg(True,{'action':data['zone_id']})
        # self.set_fail2ban_jail(data)

class get_tmp:
    pass