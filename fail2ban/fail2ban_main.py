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
#|   宝塔fail2ban管理器
#+--------------------------------------------------------------------
import public,re,os,json,system,sys

class fail2ban_main:
    base_path = "/www/server/panel"
    _set_up_path = base_path+"/plugin/fail2ban"
    _config = _set_up_path + "/config.json"
    _cdn_config = _set_up_path + "/cdn_config.json"
    _status = _set_up_path + "/status.json"
    _black_list = _set_up_path + "/black_list.json"
    _jail_local_file = "/etc/fail2ban/jail.local"


    def __init__(self):
        self._check_main_conf()
        self._fix_follow_start()
        self.sys_v = system.system().GetSystemVersion().replace(' ', '').lower()

    def _fix_follow_start(self):
        if not os.path.exists('/lib/systemd/system/fail2ban.service'):
            public.ExecShell(
                "wget -O /lib/systemd/system/fail2ban.service http://download.bt.cn/install/plugin/fail2ban/fail2ban.service -T 5")
            public.ExecShell('systemctl unmask fail2ban && systemctl daemon-reload')
        if not os.path.exists('/usr/bin/fail2ban-server'):
            public.ExecShell("ln -s /usr/local/bin/fail2ban-server /usr/bin/fail2ban-server")
            public.ExecShell("ln -s /usr/local/bin/fail2ban-client /usr/bin/fail2ban-client")
            public.ExecShell('/usr/bin/fail2ban-client stop')
            public.ExecShell('systemctl start fail2ban')

    # 备份配置文件
    def _back_file(self, file, act=None):
        file_type = "_bak"
        if act:
            file_type = "_def"
        os.system("/usr/bin/cp -p {0} {1}".format(file, file + file_type))

    # 还原配置文件
    def _restore_file(self, file, act=None):
        file_type = "_bak"
        if act:
            file_type = "_def"
        os.system("/usr/bin/cp -p {1} {0}".format(file, file + file_type))

    # 读取配置
    def _read_conf(self,path,l=None):
        conf = public.readFile(path)
        if not conf:
            if not l:
                conf = {}
            else:
                conf = []
            public.writeFile(path,json.dumps(conf))
            return conf
        return json.loads(conf)

    # 读fail2ban主配置
    def _read_conf_file(self,path):
        conf = public.readFile(path)
        if conf:
            return conf

    # 写配置
    def _write_jail_conf(self,path,values):
        c = self._read_conf(path)
        dir = ""
        if "dir" in values:
            dir = values["dir"]
        if 'zone_id' not in values:
            values["zone_id"] = ''
        if 'cdn_provide' not in values:
            values["cdn_provide"] = ''
        d = {
            "act": values["act"],
            "port": values["port"],
            "maxretry": values["maxretry"],
            "findtime": values["findtime"],
            "bantime": values["bantime"],
            "dir": dir,
            "zone_id": values["zone_id"],
            "cdn_provide":values['cdn_provide']
        }
        c[values["mode"]] = d
        public.writeFile(path,json.dumps(c))

    # 检查主配置是否存在
    def _check_main_conf(self):
        jail_local_file = "/etc/fail2ban/jail.local"
        conf = self._read_conf_file(jail_local_file)
        if not conf:
            content = """
#DEFAULT-START
[DEFAULT]
ignoreip = 127.0.0.1/8
bantime = 600
findtime = 300
maxretry = 5
banaction = firewallcmd-ipset  
action = %(action_mwl)s
#DEFAULT-END
"""
            public.writeFile(jail_local_file,content)

    # 设置ip白名单
    def set_white_ip(self,get):
        '''
        get.while_ip    "192.168.1.1"
        :param get:
        :return:
        '''
        ip_list = self.get_white_ip(get)
        ip = get.white_ip
        ip = ip.split("\n")
        if not ip_list:
            return public.returnMsg(False, "Did not find the main configuration file")
        rep_ip = "^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}($|[\/\d]+$)"
        rep_ipv6 = "^\s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*[\/\d]*$"
        for i in ip:
            if not re.search(rep_ip,i) and not re.search(rep_ipv6,i):
                return public.returnMsg(True, "IP format is incorrect")
        ip = ",".join(ip)
        jail_local_file = "/etc/fail2ban/jail.local"
        conf = self._read_conf_file(jail_local_file)
        rep = "\nignoreip\s*=\s*(.*)"
        conf = re.sub(rep,"\nignoreip = {}".format(ip),conf)
        self._back_file(jail_local_file)
        public.writeFile(jail_local_file,conf)
        # 重载
        a,e = public.ExecShell("fail2ban-client reload")
        if "ERROR" not in a:
            return public.returnMsg(True, "Added successfully")
        else:
            self._restore_file(jail_local_file)
            return public.returnMsg(True, "add failed {}".format(e))

    # 获取白名单列表
    def get_white_ip(self,get):
        conf = self._read_conf_file("/etc/fail2ban/jail.local")
        if not conf:
            return False
        rep = "\nignoreip\s*=\s*(.*)"
        ip_data = re.search(rep,conf)
        if not ip_data:
            return []
        ip_data = ip_data.group(1)
        ip_list = ip_data.split(",")
        return "\n".join(ip_list)

    # 判断规则是否已经存在
    def _check_mode_exist(self,mode):
        conf = self._read_conf(self._config)
        if mode in conf:
            return True
        return False

    # 获取信息
    def get_anti_info(self,get):
        """
        :param get:
        :return:
        """
        self._check_main_conf()
        data = self._read_conf(self._config)
        cdn_info = self.get_cdn_info(get)
        cdn_info_tmp = {}
        if not cdn_info['status']:
            cdn_info_tmp['cdn'] = {'setup': False, 'active': False}
        else:
            cdn_info_tmp['cdn'] = {'setup': True, 'active': False}
            for i in cdn_info['msg']:
                if cdn_info['msg'][i]['active'] != '1':
                    continue
                else:
                    cdn_info_tmp['cdn'] = {'setup': True, 'active': True}
        if data:
            d = {"site":[],"server":[]}
            for i in data:
                if "-scan" in i or "-cc" in i:
                    content = data[i]
                    content["mode"] = i
                    d["site"].append(content)
                else:
                    content = data[i]
                    content["mode"] = i
                    d["server"].append(content)
            d['cdn'] = cdn_info_tmp['cdn']
            return d
        return {"site":[],"server":[],'cdn':cdn_info_tmp['cdn']}

    # 判断配置是否存在
    def _check_conf_exist(self,conf,mode):
        jail_conf = self._read_conf_file(self._jail_local_file)
        self._back_file(self._jail_local_file)
        if '[{}]'.format(mode) in jail_conf:
            rep = "#{mode}-START(\n|.)+#{mode}-END".format(mode=mode)
            jail_conf = re.sub(rep,conf,jail_conf)
            public.writeFile(self._jail_local_file,jail_conf)
        else:
            public.writeFile(self._jail_local_file,conf,"a+")

    # 重载配置
    def _reload_fail2ban(self,values):
        a,e = public.ExecShell("fail2ban-client reload")
        if "ERROR" not in a:
            if 'dir' in values:
                values['dir'] = '\n'.join(values['dir'].split('|'))
            self._write_jail_conf(self._config,values)
            return public.returnMsg(True, "Successful setup")
        else:
            self._restore_file(self._jail_local_file)
            return public.returnMsg(True, "Setup failed {}".format(e))

    def _check_log_exist(self,path):
        if not os.path.exists(path):
            return public.returnMsg(False, "[ {} ] The log file does not exist and cannot be created".format(path))

    # 设置ssh防爆破
    def set_sshd_anti(self,values):
        if os.path.exists('/etc/redhat-release'):
            logpath =  '/var/log/secure'
        else:
            logpath = '/var/log/auth.log'
        """
        get.port        端口
        get.maxretry    最大请求次数
        get.findtime    周期
        get.bantime     封锁时间
        get.act         开关
        :param get:
        :return:
        """
        conf = """
#sshd-START
[sshd]
enabled = {act}
filter = sshd
port = {port}
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = %(action_mwl)s
logpath = {logpath}
#sshd-END
""".format(act=values["act"],port=values["port"],maxretry=values["maxretry"],findtime=values["findtime"],
           bantime=values["bantime"],logpath=logpath)
        # 判断配置是否存在
        self._check_conf_exist(conf,values["mode"])
        # 重载
        return self._reload_fail2ban(values)

    # 设置ftp防爆破
    def set_ftpd_anti(self,values):
        tmp = self._check_log_exist('/var/log/messages')
        if tmp:
            return tmp
        ftp_conf_file = "/www/server/pure-ftpd/etc/pure-ftpd.conf"
        conf = self._read_conf_file(ftp_conf_file)
        if not conf:
            return public.returnMsg(True, "Did not find the FTP configuration file, please confirm that ftp has been installed")
        conf = """
#ftpd-START
[ftpd]
enabled = {act}
filter = pure-ftpd
port = {port}
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = %(action_mwl)s
logpath = /var/log/messages
#ftpd-END
""".format(act=values["act"], port=values["port"], maxretry=values["maxretry"], findtime=values["findtime"], bantime=values["bantime"])
        self._check_conf_exist(conf,values["mode"])
        return self._reload_fail2ban(values)

    # 设置dovecot防爆破
    def set_dovecot_anti(self,values):
        maillog = '/var/log/mail.log'
        if "centos" in self.sys_v:
            maillog = '/var/log/maillog'
        tmp = self._check_log_exist(maillog)
        if tmp:
            return tmp
        dovecot_conf_file = "/etc/dovecot/dovecot.conf"
        conf = self._read_conf_file(dovecot_conf_file)
        if not conf:
            return public.returnMsg(True, "Did not find the Dovecot configuration file, please confirm that the post office has been installed")
        conf = """
#dovecot-START
[dovecot]
enabled = {act}
filter = dovecot
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = %(action_mwl)s
logpath = {logpath}
#dovecot-END
""".format(act=values["act"], maxretry=values["maxretry"], findtime=values["findtime"], bantime=values["bantime"],
           logpath=maillog)
        self._check_conf_exist(conf,"dovecot")
        return self._reload_fail2ban(values)

    # 设置postfix防爆破
    def set_postfix_anti(self, values):
        maillog = '/var/log/mail.log'
        if "centos" in self.sys_v:
            maillog = '/var/log/maillog'
        tmp = self._check_log_exist(maillog)
        if tmp:
            return tmp
        postfix_conf_file = "/etc/postfix/main.cf"
        conf = self._read_conf_file(postfix_conf_file)
        if not conf:
            return public.returnMsg(True, "Did not find the Postfix configuration file, please confirm that the post office has been installed")
        conf = """
#postfix-START
[postfix]
enabled = {act}
filter = aaP_postfix_1
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = %(action_mwl)s
logpath = {logpath}
#postfix-END
""".format(act=values["act"], maxretry=values["maxretry"], findtime=values["findtime"], bantime=values["bantime"],
           logpath=maillog)
        self.set_filter(t="postfix")
        self._check_conf_exist(conf, values["mode"])
        return self._reload_fail2ban(values)


    def set_filter(self,values=None,sitename=None,t=None):
        if t == "postfix":
            regex = "failregex = (?i): warning: [-._\w]+\[<HOST>\]: SASL (?:LOGIN|PLAIN|(?:CRAM|DIGEST)-MD5) authentication failed(:.*)$"
            sitename = "postfix"
            values = {}
            values["regex"] = "1"
        else:
            if values["regex"] == "scan":
                regex = "failregex = (,)?<HOST> .* ({}).* HTTP/1\..".format(values['dir'])
            elif values["regex"] == "cc":
                regex = "failregex = (,)?<HOST> .*- .*HTTP/1.* .* .*$"
            else:
                regex = values["regex"]
        conetnt = """
[Definition]
{regex}
ignoreregex =
""".format(regex=regex)
        f = "/etc/fail2ban/filter.d/aaP_{}_{}.conf".format(sitename,values["regex"])
        public.writeFile(f,conetnt)

    def _get_nginx_log_path(self,website):
        try:
            nginx_conffile = '/www/server/panel/vhost/nginx/{}.conf'.format(website)
            nginx_conf = public.readFile(nginx_conffile)
            reg = 'access_log\s+(.*\.log)'
            log_path = re.findall(reg,nginx_conf)
            if not log_path:
                return ''
            for i in log_path:
                if not os.path.exists(i):
                    continue
                return i
            return ''
        except:
            return ""

    def _get_apache_log_path(self,website):
        try:
            apache_conffile = '/www/server/panel/vhost/apache/{}.conf'.format(website)
            apache_conf = public.readFile(apache_conffile)
            reg = 'CustomLog\s+"(.*)"\s+combined'
            log_path = re.search(reg,apache_conf)
            apache_log_path = ""
            if log_path:
                apache_log_path = log_path.groups(1)[0]
            return apache_log_path
        except:
            return ""

    def _get_ols_log_path(self,website):
        try:
            ols_conffile = '/www/server/panel/vhost/openlitespeed/detail/{}.conf'.format(website)
            ols_conf = public.readFile(ols_conffile)
            reg = 'accesslog\s+(.*)\s+{'
            log_path = re.search(reg,ols_conf)
            ols_log_path = ""
            if log_path:
                ols_log_path = log_path.groups(1)[0].replace('$VH_NAME',website)
            return ols_log_path
        except:
            return ""

    def _get_website_log_path(self,website,web_server):
        data = {"nginx":self._get_nginx_log_path(website),
                "apache":self._get_apache_log_path(website),
                "openlitespeed":self._get_ols_log_path(website)
                }
        error = self._check_log_exist(data[web_server])
        if error:
            return error
        return public.returnMsg(True,data[web_server])

    # 设置站点目录防扫描
    def set_scan_anti(self,values):
        """
        get.sitename    站点名
        get.dir         不想被扫描的目录
        :param get:
        :return:
        """
        sitename = values["mode"].split("-")[:-1]
        sitename = "-".join(sitename)
        values['sitename'] = sitename
        web_server = public.get_webserver()
        values["dir"] = '|'.join([x.strip() for x in values["dir"].split('\n') if x])

        log_path = self._get_website_log_path(sitename,web_server)
        if not log_path['status']:
            return log_path
        action = "%(action_mwl)s"
        if 'cdn_provide' in values and values['cdn_provide']:
            if 'zone_id' not in values:
                return public.returnMsg(False,'Please fill in the zone id first')
            result = self.active_cdn(values)
            if not result['status']:
                return result
            action = result['msg']['action']
        conf = """
#{sitename}-scan-START
[{sitename}-scan]
enabled = {act}
filter = aaP_{sitename}_scan
port = {port}
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = {action}
logpath = {log_path}
#{sitename}-scan-END
""".format(act=values["act"], port=values["port"], maxretry=values["maxretry"], findtime=values["findtime"],
           bantime=values["bantime"],log_path=log_path['msg'],sitename=sitename,action=action)

        self._check_conf_exist(conf,values["mode"])
        values["regex"] = "scan"
        self.set_filter(values,sitename)
        result = self._reload_fail2ban(values)
        if result["status"] == False:
            f = "/etc/fail2ban/filter.d/aaP_{}_scan.conf".format(sitename)
            if os.path.exists(f):
                os.remove(f)
        return result

    def set_cdn_info(self,get):
        values = self._check_get_args(get)
        if "status" in values.keys():
            return values
        cdn_provide = get.cdn_provide.strip()
        data = public.readFile(self._cdn_config)
        if not data:
            data = {cdn_provide:{'user':values['user'],'token':values['token'],'active':values['active']}}
        else:
            data = json.loads(data)
            data[cdn_provide] = {'user':values['user'],'token':values['token'],'active':values['active']}
        public.writeFile(self._cdn_config, json.dumps(data))
        return public.ReturnMsg(True,'Setup successfully')

    def get_cdn_info(self,get):
        data = public.readFile(self._cdn_config)
        if not data:
            return public.ReturnMsg(False,'CDN provide not set.Please set in [CDN Provide]')
        return public.ReturnMsg(True,json.loads(data))

    def load_cdn_module(self,cdn_provide):
        # 加载需要的dns模块
        sys.path.insert(0,self.base_path+"/plugin/fail2ban/cdn")
        cdn_module = __import__('{}'.format(cdn_provide))
        return eval('cdn_module.set_cdn_defence()')

    def test_cdn_auth_info(self,get):
        values = self._check_get_args(get)
        if "status" in values.keys():
            return values
        cdn_module = self.load_cdn_module(values['cdn_provide'])
        result = cdn_module.check_auth_info(values)
        if result:
            return public.returnMsg(True,'connection succeeded')
        return public.returnMsg(False, 'Connection failed')

    def active_cdn(self,values):
        """
        get.mode 需要开启cdn的网站
        get.cdn_provide
        get.zone_id 域名的ID
        :param get:
        :return:
        """
        if values['type'] == 'edit' and not self._check_mode_exist(values['mode']):
            return public.returnMsg(False,'The specified rule was not found')
        get_tmp.mode = values['mode']
        cdn_info = self.get_cdn_info(get_tmp)
        if not cdn_info['status']:
            return cdn_info
        cdn_info = cdn_info['msg'][values['cdn_provide']]
        if 'active' not in cdn_info:
            return public.returnMsg(False,'CDN Provide settings are not activated')
        if cdn_info['active'] != '1':
            return public.returnMsg(False,'CDN Provide settings are not activated')
        self.del_anti(get_tmp)
        cf = self.load_cdn_module(values['cdn_provide'])
        return cf.main(values)

    # 设置cc简单防御
    def set_cc_anti(self,values):
        sitename = values["mode"].split("-")[:-1]
        sitename = "-".join(sitename)
        values['sitename'] = sitename
        web_server = public.get_webserver()
        log_path = self._get_website_log_path(sitename,web_server)
        if not log_path['status']:
            return log_path
        action = "%(action_mwl)s"
        if 'cdn_provide' in values and values['cdn_provide']:
            if 'zone_id' not in values:
                return public.returnMsg(False,'Please fill in the zone id first')
            result = self.active_cdn(values)
            if not result['status']:
                return result
            action = result['msg']['action']
        conf = """
#{sitename}-cc-START
[{sitename}-cc]
enabled = {act}
filter = aaP_{sitename}_cc
port = {port}
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = {action}
logpath = {log_path}
#{sitename}-cc-END
""".format(act=values["act"], port=values["port"], maxretry=values["maxretry"], findtime=values["findtime"],
           bantime=values["bantime"],log_path=log_path['msg'],sitename=sitename,action=action)

        self._check_conf_exist(conf, values["mode"])
        values["regex"] = "cc"
        self.set_filter(values,sitename)
        result = self._reload_fail2ban(values)
        if result["status"] == False:
            f = "/etc/fail2ban/filter.d/aaP_{}_cc.conf".format(sitename)
            if os.path.exists(f):
                os.remove(f)
        return result

    # 获取mysql数据目录
    def _get_mysql_storage_dir(self):
        data = {}
        try:
            public.CheckMyCnf()
            myfile = '/etc/my.cnf'
            mycnf = public.readFile(myfile)
            rep = "datadir\s*=\s*(.+)\n"
            data['datadir'] = re.search(rep, mycnf).groups()[0]
        except:
            data['datadir'] = '/www/server/data'
        return data

    # mysql防爆破
    def set_mysql_anti(self, values):
        import socket
        hostname = socket.gethostname()
        postfix_conf_file = "/etc/my.cnf"
        conf = self._read_conf_file(postfix_conf_file)
        if not conf:
            return public.returnMsg(True, "Did not find the Mysql configuration file, please confirm that the post office has been installed")
        datadir = self._get_mysql_storage_dir()
        tmp = self._check_log_exist("{}/{}.err".format(datadir["datadir"],hostname))
        if tmp:
            return tmp
        conf = """
#mysql-START
[mysql]
enabled = {act}
filter = mysqld-auth
maxretry = {maxretry}
findtime = {findtime}
bantime = {bantime}
action = %(action_mwl)s
logpath = {datadir}/{hostname}.err
#mysql-END
""".format(act=values["act"], maxretry=values["maxretry"], findtime=values["findtime"], bantime=values["bantime"],datadir=datadir["datadir"],hostname=hostname)
        self._check_conf_exist(conf, values["mode"])
        return self._reload_fail2ban(values)

    def set_anti(self,get):
        values = self._check_get_args(get)
        if "status" in values.keys():
            return values
        if values["type"] == "add":
            if self._check_mode_exist(values["mode"]):
                return public.returnMsg(False, "Already exists {}".format(values["mode"]))
        default_filter = ["mysql","postfix","dovecot","sshd","ftpd"]
        if values["mode"] == "sshd_service":
            values["mode"] = "sshd"
        if values["mode"] == "ftpd_service":
            values["mode"] = "ftpd"
        if values["mode"] in default_filter:
            a="self.set_"+values["mode"]+"_anti(values)"
            return eval(a)
        if "-cc" in values["mode"]:
            return self.set_cc_anti(values)
        if "-scan" in values["mode"]:
            return self.set_scan_anti(values)
        return public.returnMsg(False, "The parameters are incorrect, please re-enter")

    def del_action(self,data):
        if 'zone_id' not in data:
            return False
        action = '/etc/fail2ban/action.d/{}.conf'.format(data['zone_id'])
        if not os.path.exists(action):
            return False
        os.remove(action)

    # 删除防爆破
    def del_anti(self,get):
        values = self._check_get_args(get)
        if "status" in values.keys():
            return values
        conf = self._read_conf(self._config)
        if values["mode"] in conf:
            self.del_action(conf[values["mode"]])
            del(conf[values["mode"]])
            public.writeFile(self._config,json.dumps(conf))
        jail_conf = self._read_conf_file(self._jail_local_file)
        rep = "\n#{mode}-START(\n|.)+#{mode}-END".format(mode=values["mode"])
        jail_conf = re.sub(rep, "", jail_conf)
        public.writeFile(self._jail_local_file, jail_conf)
        public.ExecShell("fail2ban-client reload")
        return public.returnMsg(True,"Successfully deleted")

    # 更新fail2ban源码
    def update_fail2ban(self):
        # 备份旧fail2ban
        shell_str = """
fail2ban-client stop
mv /etc/fail2ban /etc/fail2ban_bak
git clone https://github.com/fail2ban/fail2ban.git
cd fail2ban
sudo python setup.py install
cp /etc/fail2ban_bak/jail.local /etc/fail2ban/jail.local
cp /etc/fail2ban_bak/filter.d/aaP_* /etc/fail2ban/filter.d/
"""
        os.system(shell_str)
        a,e = public.ExecShell("fail2ban-client start")
        if "ERROR" in a:
            return public.returnMsg(False, "Upgrade failed {}".format(a))
        return public.returnMsg(True, "Update successed")

    # 获取状态
    def get_status(self,get):
        values = self._check_get_args(get)
        if "status" in values.keys():
            return values
        conf = self.get_anti_info(get)
        for c in conf:
            if c == 'cdn':
                continue
            for i in conf[c]:
                if values["mode"] == i["mode"]:
                    if i["act"] == "false":
                        return public.returnMsg(False, "Protection has been turned off")


        a,e = public.ExecShell("/usr/bin/fail2ban-client status {}".format(values["mode"]))
        if "ERROR" not in a:
            data = {}
            currently_failed = re.search("Currently\s*failed:\s*(\d+)",a)
            total_failed = re.search("Total\s*failed:\s*(\d+)",a)
            file_list = re.search("File\s*list:\s*([\w\/\.]+)",a)
            if not file_list:
                file_list = "/tmp"
            currently_banned = re.search("Currently\s*banned:\s*(\d+)",a)
            total_banned = re.search("Total\s*banned:\s*(\d+)",a)
            banned_ip_list = re.search("Banned\s*IP\s*list:\s*([\w\s\.\:]+)",a)

            if not (currently_failed and total_failed and file_list and currently_banned and total_banned and banned_ip_list):
                return public.returnMsg(False, "There may be a problem with this monitoring, please delete and re-create")
            data["currently_failed"] = currently_failed.group(1)
            data["total_failed"] = total_failed.group(1)
            try:
                data["file_list"] = file_list.group(1)
            except:
                data["file_list"] = ""
            data["currently_banned"] = currently_banned.group(1)
            data["total_banned"] = total_banned.group(1)
            data["banned_ip_list"] = banned_ip_list.group(1).strip("\n").split()
            return public.returnMsg(True, data)
        else:
            return public.returnMsg(False, "Acquisition failed，{}".format(a))

    # 解禁ip
    def ban_ip_release(self,get):
        """
        get.ip
        get.mode
        :param get:
        :return:
        """
        values = self._check_get_args(get)
        if "status" in values.keys():
            return values
        shell_str = "fail2ban-client set {mode} unbanip {ip}".format(mode=values["mode"],ip=values["ip"])
        os.system(shell_str)
        return public.returnMsg(True, "Unlocked successfully")

    # 获取状态
    def get_fail2ban_status(self,get):
        sock = "/www/server/panel/plugin/fail2ban/fail2ban.sock"
        if os.path.exists(sock):
            return True
        return False

    # 设置fail2ban服务状态
    def set_fail2ban_status(self,get):
        if get.type == "reload":
            if not self.get_fail2ban_status(get):
                return public.returnMsg(False, "Service is not enabled, please open the service first")
            a, e = public.ExecShell("fail2ban-client reload")
            if "ERROR" not in a:
                return public.returnMsg(True, "Reload success")
            else:
                self._restore_file(self._jail_local_file)
                return public.returnMsg(True, "Reload failure {}".format(e))
        if get.type == "start":
            if not self.get_fail2ban_status(get):
                a,e = public.ExecShell("fail2ban-client start")
                if "ERROR" in a:
                    return public.returnMsg(True, "Startup failed")
                return public.returnMsg(True, "Successful startup")
            return public.returnMsg(False, "Service is already open")

        if get.type == "stop":
            if self.get_fail2ban_status(get):
                public.ExecShell("fail2ban-client stop")
                return public.returnMsg(True, "Stop successful")
            return public.returnMsg(False, "Service has stopped")

        if get.type == "restart":
            public.ExecShell("fail2ban-client restart")
            return public.returnMsg(True, "Restart successfully")

    # 获取允许设置的模式列表
    def get_mode_list(self,get):
        mode_l = {"server":
                      [{"service":"sshd","port":"22"},
                       {"service":"mysql","port":"3306"},
                       {"service":"dovecot","port":"110,143,993,995"},
                       {"service":"postfix","port":"25,465,587"},
                       {"service":"ftpd","port":"21"}],
                  "site":
                      ["site-cc","site-scan"]}
        return mode_l

    # 获取所有站点
    def get_all_sitename(self,get):
        site = {}
        site_list = public.M("sites").field("id,name").select()
        for i in site_list:
            domain_list = public.M("domain").where("pid=?", (i["id"],)).field("name").select()
            l = []
            for domain in domain_list:
                l.append(domain["name"])
            site[i["name"]] = l
        return site

    # def get_black_list(self,get):
    #     conf = self._read_conf(self._black_list,l=1)
    #     return conf
    # 获取黑名单列表
    def get_black_list(self,get):
        conf = self._read_conf(self._black_list,l=1)
        if not conf:
            return ''
        if not conf:
            return []
        return "\n".join(conf)

    # 设置黑名单
    def ban_ip(self,get):
        ip_list = self.get_black_list(get).split('\n')
        new_ip_list = get.black_ip.split('\n')
        add_ip_list = [new_ip for new_ip in new_ip_list if new_ip not in ip_list]
        del_ip_list = [del_ip for del_ip in ip_list if del_ip not in new_ip_list]
        rep_ip = "^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}($|[\/\d]+$)"
        rep_ipv6 = "^\s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*$"
        data = self._read_conf(self._config)
        conf = self._read_conf(self._black_list, l=1)
        # 传入的IP为空时删除所有黑名单
        if not get.black_ip:
            for d in data:
                for ip in ip_list:
                    public.ExecShell('fail2ban-client -vvv set {jail} unbanip {ip}'.format(jail=d, ip=ip))
            public.writeFile(self._black_list, json.dumps([]))
            return public.returnMsg(True, "ban IP successfully")
        # 检查IP格式
        for ip in add_ip_list:
            if not re.search(rep_ip,ip) and not re.search(rep_ipv6,ip):
                return public.returnMsg(False, "IP format is incorrect {}".format(ip))
        # 添加新域名到黑名单
        for d in data:
            for ip in add_ip_list:
                public.ExecShell('fail2ban-client -vvv set {jail} banip {ip}'.format(jail=d,ip=ip))
        # 检查是否有清理掉的IP
        for d in data:
            for ip in del_ip_list:
                public.ExecShell('fail2ban-client -vvv set {jail} unbanip {ip}'.format(jail=d,ip=ip))

        for ip in add_ip_list:
            conf.append(ip)
        public.writeFile(self._black_list,json.dumps(conf))
        return public.returnMsg(True, "ban IP successfully")

    # 删除黑名单
    def unban_ip(self,get):
        values = self._check_get_args(get)
        if "status" in values.keys():
            return values
        data = self._read_conf(self._config,l=1)
        for d in data:
            public.ExecShell('fail2ban-client set {jail} unbanip {ip}'.format(jail=d, ip=values["ip"]))
        conf = self._read_conf(self._black_list)
        conf.remove(values["ip"])
        public.writeFile(self._black_list,json.dumps(conf))
        return public.returnMsg(True, "unban IP successfully")

    # 检查ssh端口
    def _check_ssh_port(self):
        rep = "\nPort\s+(\d+)"
        c_file = "/etc/ssh/sshd_config"
        c = public.readFile(c_file)
        if not c:
            return False
        result = re.search(rep,c)
        if not c:
            return "22"
        return result.group(1)

    # 检查ftp端口
    def check_ftp_port(self):
        pass

    # 验证前端输入
    def _check_get_args(self,get):
        values = {}
        if hasattr(get, "user"):
            try:
                if not re.search('[\w\-\_]+@[\w\-\_\.]+',get.user):
                    return public.ReturnMsg(False, "[Email] ,Please pass in a email address")
                values["user"] = get.user
            except:
                return public.ReturnMsg(False, "[Email] ,Please pass in a email address")
        if hasattr(get, "token"):
            if not get.token:
                return public.ReturnMsg(False, "[Token] can not be emtpy")
            values["token"] = get.token
        if hasattr(get, "active"):
            if not get.active:
                return public.ReturnMsg(False, "[Active] can not be emtpy")
            values["active"] = get.active
        if hasattr(get, "type"):
            if get.type in ["edit","add"]:
                values["type"] = get.type
            else:
                return public.ReturnMsg(False, "type ,Incoming type error")
        if hasattr(get, "cdn_provide"):
            if get.cdn_provide in ["cloudflare",""]:
                values["cdn_provide"] = get.cdn_provide
            else:
                return public.ReturnMsg(False, "Only support cloudflare")
        if hasattr(get, "act"):
            if get.act in ["true","false"]:
                values["act"] = str(get.act)
            else:
                return public.ReturnMsg(False, "act ,Incoming type error")
        if hasattr(get, "findtime"):
            try:
                values["findtime"] = int(get.findtime)
            except:
                return public.ReturnMsg(False, "findtime ,Please pass in a positive integer")
        if hasattr(get, "maxretry"):
            try:
                values["maxretry"] = int(get.maxretry)
            except:
                return public.ReturnMsg(False, "maxretry ,Please pass in a positive integer")
        if hasattr(get,"bantime"):
            try:
                values["bantime"] = int(get.bantime)
            except:
                return public.ReturnMsg(False, "bantime ,Please pass in a positive integer")
        if hasattr(get,"port"):
            try:
                port_l = get.port.split(",")
                for i in port_l:
                    if int(i) <= 0 or 65535 < int(i):
                        return public.ReturnMsg(False, "port:{} ,Please pass in the number in the range 0-65535".format(i))
                values["port"] = get.port
            except:
                return public.ReturnMsg(False, "port:{} ,Please pass in the number in the range 0-65535".format(port_l))
        if hasattr(get,"mode"):
            rep = "[^\w\.\_\-]+"
            if re.search(rep, get.mode):
                return public.returnMsg(False, "mode ,The parameter has special characters, please re-enter")
            values["mode"] = str(get.mode)
        if hasattr(get,"zone_id"):
            if hasattr(get, "cdn_provide") and get.cdn_provide and not get.zone_id:
                return public.returnMsg(False, "[zone_id] can not be empty")
            values["zone_id"] = str(get.zone_id)

        if hasattr(get,"dir"):
            rep = "[^\w\.\_\-\\\/\s]+"
            if not get.dir:
                return public.returnMsg(False, "dir ,can not be empty")
            if re.search(rep, get.dir):
                return public.returnMsg(False, "dir ,The parameter has special characters, please re-enter")
            values["dir"] = str(get.dir)
        if hasattr(get,"ip"):
            rep = "^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$"
            rep_ipv6 = "^\s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*$"
            if not re.search(rep, get.ip) and not re.search(rep_ipv6,get.ip):
                return public.returnMsg(False, "ip , wrong format")
            values["ip"] = str(get.ip)
        return values

class get_tmp:
    pass