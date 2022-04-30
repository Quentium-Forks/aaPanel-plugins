#coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2019 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: zhwen <zhw@bt.cn>
# +-------------------------------------------------------------------

#--------------------------------
# 反垃圾邮件插件
#--------------------------------

import os,time
from re import search,sub
from json import loads,dumps
os.chdir("/www/server/panel")
import public

class anti_spam_main:

    _amavisd_conf = "/etc/amavisd/amavisd.conf"
    _clamd_conf = "/etc/clamd.d/scan.conf"
    _count_json = '/www/server/panel/plugin/anti_spam/data/count.json'
    _parameters = {'max_servers': 'Maximum number of worker processes',
                  'local_domains_maps': 'Email domain name to be protected',
                  'inet_socket_bind': 'Listening IP address',
                  'inet_socket_port': 'Listening port',
                  'sa_tag_level_deflt': 'When the mail score is less than it, add the mail score to the mail source',
                  'sa_tag2_level_deflt': 'When the mail score is less than it, add content to the mail subject (default is added **Spam**)',
                  'final_virus_destiny': 'What action to take when a virus is detected',
                  'final_banned_destiny': 'What action to perform when prohibited content is detected',
                  'final_spam_destiny': 'What action to perform when spam is detected',
                  'final_bad_header_destiny': 'What action to perform when a bad letter is detected',
                  'sa_spam_subject_tag': 'Content added to the message header when spam is detected',
                  'sa_mail_body_size_limit': 'Maximum size of mail to scan'}

    def __init__(self):
        self._init_spam_conf()

    # 初始化网关配置
    def _init_spam_conf(self):
        """
        初始化反垃圾组件配置参数
        author: zhwwen
        modify at: 2020-06-06
        """
        if os.path.exists('/etc/redhat-release'):
            self._init_syslog_centos_conf()
        else:
            self._init_syslog_ubuntu_conf()

    def _init_syslog_centos_conf(self):
        """
        初始化反日志
        author: zhwwen
        modify at: 2020-06-06
        """
        public.ExecShell('yum install rsyslog -y')
        cfg = '/etc/rsyslog.conf'
        conf = public.readFile(cfg)
        if 'mail.notice' in conf:
            return True
        add_conf = "\nmail.notice /var/log/amavis.log"
        public.writeFile(cfg,conf+add_conf)
        public.ExecShell('touch /var/log/amavis.log && '
                         'chown amavis.amavis /var/log/amavis.log &&'
                         'systemctl restart rsyslog')
        return True

    def _init_syslog_ubuntu_conf(self):
        public.ExecShell('apt install rsyslog -y')
        cfg = '/etc/rsyslog.d/50-default.conf'
        if os.path.exists(cfg):
            cfg = '/etc/rsyslog.conf'
        conf = public.readFile(cfg)
        if not conf:
            return False
        if 'mail.notice' in conf:
            return True
        add_conf = "\nmail.notice /var/log/amavis.log"
        public.writeFile(cfg,conf+add_conf)
        public.ExecShell('touch /var/log/amavis.log && '
                         'chown syslog.adm /var/log/amavis.log &&'
                         'systemctl restart rsyslog')
        return True

    def set_spam_parameter(self,get):
        """
        设置反垃圾常用参数
        author: zhwwen
        modify at: 2020-06-06
        """
        if not os.path.exists('/etc/redhat-release'):
            self._set_spam_ubuntu_parameter(get)
            public.ExecShell('systemctl restart amavis')
        else:
            conf = public.readFile(self._amavisd_conf)
            for p in self._parameters:
                value = get[p]
                reg = '\n\${}\s*=\s*(.*);'.format(p)
                new_parameters = '\n${} = {};'.format(p, value)
                if 'inet_socket_bind' not in conf:
                    conf = "${} = '{}';\n".format(p,value) + conf
                if p == 'sa_spam_subject_tag':
                    new_parameters = "\n${} = '{}';".format(p, value)
                if p in ['sa_mail_body_size_limit']:
                    new_parameters = "\n${} = '{}*1024';".format(p, value)
                if p in ['local_domains_maps']:
                    reg = '\n@{} = (.*);'.format(p)
                    value = self._process_local_domain(value,action='set')
                    new_parameters = '\n@{} = {};'.format(p, value)
                conf = sub(reg,new_parameters,conf)
            public.writeFile(self._amavisd_conf, conf)
        public.ExecShell('systemctl restart amavisd')
        return public.returnMsg(True,"Successfully modified")

    def _set_spam_ubuntu_parameter(self,get):
        domain_id = '/etc/amavis/conf.d/05-domain_id'
        ubuntu_defaults = '/etc/amavis/conf.d/21-ubuntu_defaults'
        debian_defaults = '/etc/amavis/conf.d/20-debian_defaults'
        domain_id_conf = public.readFile(domain_id)
        ubuntu_defaults_conf = public.readFile(ubuntu_defaults)
        debian_defaults_conf = public.readFile(debian_defaults)
        for p in self._parameters:
            value = get[p]
            reg = '\n\${}\s*=.*;'.format(p)
            if p in ['local_domains_maps']:
                reg = '\n@{} = (.*);'.format('local_domains_acl')
                value = '("'+'","'.join(value.strip('\n').split('\n'))+'")'
                new_parameters = '\n@{} = {};'.format('local_domains_acl', value)
                domain_id_conf = sub(reg, new_parameters, domain_id_conf)
            elif p in ['final_virus_destiny','final_banned_destiny','final_spam_destiny','final_bad_header_destiny']:
                new_parameters = '\n${} = {};'.format(p, value)
                ubuntu_defaults_conf = sub(reg, new_parameters, ubuntu_defaults_conf)
            else:
                new_parameters = '\n${} = {};'.format(p, value)
                if p in ['sa_spam_subject_tag','inet_socket_bind']:
                    new_parameters = "\n${} = '{}';".format(p, value)
                if p in ['sa_mail_body_size_limit']:
                    new_parameters = "\n${} = '{}*1024';".format(p, value)
                if 'inet_socket_bind' not in debian_defaults_conf:
                    debian_defaults_conf = "${} = '{}';\n".format(p,value) + debian_defaults_conf
                debian_defaults_conf = sub(reg, new_parameters, debian_defaults_conf)
        public.writeFile(domain_id,domain_id_conf)
        public.writeFile(ubuntu_defaults,ubuntu_defaults_conf)
        public.writeFile(debian_defaults,debian_defaults_conf)

    def get_spam_parameter(self,get):
        """
        获取反垃圾参数
        author: zhwwen
        modify at: 2020-06-06
        """
        if not os.path.exists('/etc/redhat-release'):
            return self._get_spam_ubuntu_parameter(get)
        else:
            conf = public.readFile(self._amavisd_conf)
            data = {}
            for p in self._parameters:
                reg = '\n\${}\s*=\s*[\'\"]?(.*?)[\'\"]?;'.format(p)
                if p in ['local_domains_maps']:
                    reg = '\n\@{}\s*=\s*(.*);'.format(p)
                tmp = search(reg,conf)
                if not tmp:
                    data[p] = {'description':self._parameters[p],'value':''}
                    continue
                data[p] = {'description': self._parameters[p], 'value': tmp.groups(1)[0]}
                if p in ['sa_mail_body_size_limit']:
                    data[p] = {'description': self._parameters[p], 'value': tmp.groups(1)[0].split('*')[0]}
            if not data['inet_socket_bind']['value']:
                data['inet_socket_bind']['value'] = '127.0.0.1'
            data = self._process_local_domain(data,action='get')
            return data

    def _get_spam_ubuntu_parameter(self,get):
        domain_id = '/etc/amavis/conf.d/05-domain_id'
        ubuntu_defaults = '/etc/amavis/conf.d/21-ubuntu_defaults'
        debian_defaults = '/etc/amavis/conf.d/20-debian_defaults'
        data = {}
        for p in self._parameters:
            reg = '\n\${}\s*=\s*[\'\"]?(.*?)[\'\"]?;'.format(p)
            if p in ['local_domains_maps']:
                domain_id_conf = public.readFile(domain_id)
                reg = '\n\@{}\s*=\s*\((.*)\);'.format('local_domains_acl')
                tmp = search(reg, domain_id_conf)
            elif p in ['final_virus_destiny','final_banned_destiny','final_spam_destiny','final_bad_header_destiny']:
                ubuntu_defaults_conf = public.readFile(ubuntu_defaults)
                tmp = search(reg, ubuntu_defaults_conf)
            else:
                debian_defaults_conf = public.readFile(debian_defaults)
                tmp = search(reg, debian_defaults_conf)
            if not tmp:
                data[p] = {'description': self._parameters[p], 'value': ''}
                continue
            data[p] = {'description': self._parameters[p], 'value': tmp.groups(1)[0]}
        data['local_domains_maps']['value'] = data['local_domains_maps']['value'].replace('"','').replace(',','\n')
        data['sa_mail_body_size_limit']['value'] = data['sa_mail_body_size_limit']['value'].split('*')[0]
        return data

    def _process_local_domain(self,parameter,action=None):
        if action == 'get':
            data = parameter['local_domains_maps']['value']
            data = data.replace('( ','').replace(' )','')
            data = '\n'.join(loads(data))
            parameter['local_domains_maps']['value'] = data
            return parameter
        else:
            data = parameter.split('\n')
            data = '( '+str(data)+' )'
            data = data.replace("'",'"')
            return data

    def get_process_count(self,get):
        cfg = public.readFile(self._count_json)
        if not cfg:
            return {'ban_file':0,'spam':0,'virus':0}
        return loads(cfg)

    def _get_day_range(self,days):
        timestamp = 0
        days_list = []
        for day in range(int(days)):
            tmp_day = time.time() - timestamp
            days_list.append(time.strftime("%Y-%m-%d", time.localtime(tmp_day)))
            timestamp += 86400
        return days_list


    def get_someday_record(self,get):
        '''
        获取某个时间段内的数据
        今天/昨天/7天
        date = today/yesterday/7
        '''
        if get.date == 'today':
            today = time.strftime("%Y-%m-%d", time.localtime())
            cfgd = '/www/server/panel/plugin/anti_spam/data/{}.json'.format(today)
            conf = public.readFile(cfgd)
            if not conf:
                conf = {'ban_file': {}, 'spam': {}, 'virus': {}}
                for t in range(1, 25):
                    conf['ban_file'][str(t)] = 0
                    conf['spam'][str(t)] = 0
                    conf['virus'][str(t)] = 0
                return conf
            return loads(conf)
        if get.date == 'yesterday':
            yesterday = time.time() - 86400
            yesterday = time.strftime("%Y-%m-%d", time.localtime(yesterday))
            cfgd = '/www/server/panel/plugin/anti_spam/data/{}.json'.format(yesterday)
            conf = public.readFile(cfgd)
            if not conf:
                conf = {'ban_file': {}, 'spam': {}, 'virus': {}}
                for t in range(1, 25):
                    conf['ban_file'][str(t)] = 0
                    conf['spam'][str(t)] = 0
                    conf['virus'][str(t)] = 0
                return conf
            return loads(conf)
        if get.date == '7':
            days_data = []
            days = self._get_day_range(get.date)
            for d in days:
                cfgd = '/www/server/panel/plugin/anti_spam/data/{}.json'.format(d)
                conf = public.readFile(cfgd)
                if not conf:
                    conf = {'ban_file': {}, 'spam': {}, 'virus': {}}
                    for t in range(1, 25):
                        conf['ban_file'][str(t)] = 0
                        conf['spam'][str(t)] = 0
                        conf['virus'][str(t)] = 0
                    days_data.append(conf)
                    continue
                days_data.append(loads(conf))
            return days_data

    def get_service_status(self,get):
        amavisd = True if os.path.exists('/var/run/amavisd/amavisd.pid') else False
        clamd = True if os.path.exists('/var/run/clamd.amavisd/clamd.pid') else False
        try:
            log_monitor = True if public.ExecShell('ps aux|grep anti_spam_server|grep -v "grep"|wc -l')[0].split('\n')[0] != "0" else False
        except:
            log_monitor = False
        try:
            spamassassin = True if public.ExecShell('ps aux|grep spamd|grep -v "grep"|wc -l')[0].split('\n')[0] != "0" else False
        except:
            spamassassin = False
        if not os.path.exists('/etc/redhat-release'):
            amavisd = True if os.path.exists('/var/run/amavis/amavisd.pid') else False
            clamd = True if os.path.exists('/var/run/clamav/clamd.ctl') else False
        return {'amavisd':{'status':amavisd,'ps':'Used to schedule mail scanning'},
                'clamd@amavisd':{'status':clamd,'ps':'Used to scan mail viruses'},
                'spamassassin':{'status':spamassassin,'ps':'Used to scan spam'},
                'log_monitor':{'status':log_monitor,'ps':'Used to record the number of interceptions'}}

    def set_service_status(self,get):
        if get.service == 'log_monitor':
            public.ExecShell('/etc/init.d/anti_spam_service {}'.format(get.act))
            return public.returnMsg(True,"Set up successfully")
        if os.path.exists('/etc/redhat-release'):
            public.ExecShell('systemctl {} {}'.format(get.act,get.service))
            if get.service == 'clamd@amavisd':
                if get.act in ('start', 'restart'):
                    self.__clamd_switch('open')
                elif get.act == 'stop':
                    self.__clamd_switch('close')
        else:
            if get.service == 'amavisd':
                public.ExecShell('systemctl {} {}'.format(get.act, 'amavis'))
            elif get.service == 'clamd@amavisd':
                public.ExecShell('systemctl {} {}'.format(get.act, 'clamav-daemon'))
            else:
                public.ExecShell('systemctl {} {}'.format(get.act, 'spamassassin'))
        time.sleep(1)
        status = self.get_service_status(get)
        if get.act == 'start':
            if status[get.service]:
                return public.returnMsg(True,"Set up successfully")
            return public.returnMsg(False,"Setup failed")
        return public.returnMsg(True, "Set up successfully")


    def get_default_parameter(self,get):
        parameters = {'max_servers':'1',
                      'local_domains_maps':'.$mydomain',
                      'inet_socket_bind':'127.0.0.1',
                      'inet_socket_port':'10024',
                      'sa_tag_level_deflt':'2.0',
                      'sa_tag2_level_deflt':'6.2',
                      'final_virus_destiny':'D_DISCARD',
                      'final_banned_destiny':'D_BOUNCE',
                      'final_spam_destiny':'D_REJECT',
                      'final_bad_header_destiny':'D_PASS',
                      'sa_spam_subject_tag':'**Spam**',
                      'sa_mail_body_size_limit':'4'}
        return parameters

    # 检查传入参数
    def _check_args(self,get):
        # 检查amavisd设置的常用参数
        if hasattr(get,'max_servers'):
            try:
                int(get.max_servers)
                if get.max_servers[0] == '-':
                    return public.returnMsg(False, "max_servers Only positive integers can be filled")
            except:
                return public.returnMsg(False,"max_servers Only positive integers can be filled")
        if hasattr(get,'inet_socket_bind'):
            rep_ip = "^(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}$"
            rep_ipv6 = "^\s*((([0-9A-Fa-f]{1,4}:){7}(([0-9A-Fa-f]{1,4})|:))|(([0-9A-Fa-f]{1,4}:){6}(:|((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})|(:[0-9A-Fa-f]{1,4})))|(([0-9A-Fa-f]{1,4}:){5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){4}(:[0-9A-Fa-f]{1,4}){0,1}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){3}(:[0-9A-Fa-f]{1,4}){0,2}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:){2}(:[0-9A-Fa-f]{1,4}){0,3}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(([0-9A-Fa-f]{1,4}:)(:[0-9A-Fa-f]{1,4}){0,4}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(:(:[0-9A-Fa-f]{1,4}){0,5}((:((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})?)|((:[0-9A-Fa-f]{1,4}){1,2})))|(((25[0-5]|2[0-4]\d|[01]?\d{1,2})(\.(25[0-5]|2[0-4]\d|[01]?\d{1,2})){3})))(%.+)?\s*$"
            if not search(rep_ip, get.inet_socket_bind):
                return public.returnMsg(False,"inet_socket_bind Please enter the correct IP address, if you want to monitor all IP please enter 0.0.0.0")
            if not search(rep_ipv6, get.inet_socket_bind):
                return public.returnMsg(False,"inet_socket_bind Please enter the correct IP address, if you want to monitor all IP please enter 0.0.0.0")
        if hasattr(get,'inet_socket_port'):
            try:
                if int(get.max_servers) < 1 or int(get.max_servers) > 65535:
                    return public.returnMsg(False, "inet_socket_port Only fill in numbers between 1-65535")
                if get.max_servers[0] == '-':
                    return public.returnMsg(False, "inet_socket_port Only fill in numbers between 1-65535")
            except:
                return public.returnMsg(False,"inet_socket_port Only fill in numbers between 1-65535")
        if hasattr(get,'sa_tag_level_deflt'):
            try:
                int(get.max_servers)
            except:
                return public.returnMsg(False,"max_servers Only fill in numbers")
        if hasattr(get,'sa_tag2_level_deflt'):
            try:
                int(get.max_servers)
            except:
                return public.returnMsg(False,"max_servers Only fill in numbers")
        if hasattr(get,'sa_mail_body_size_limit'):
            try:
                int(get.max_servers)
            except:
                return public.returnMsg(False,"max_servers Only fill in numbers")

    def __clamd_switch(self, act):
        '''
        打开或者关闭amavisd配置中的clamd
        :param act:
        :return:
        '''
        import re

        config = public.readFile('/etc/amavisd/amavisd.conf')
        try:
            data = re.findall('#open_clamd.+#end_clamd', config, re.S)[0].strip()
        except:
            return public.returnMsg(False, 'No corresponding configuration found!')
        # print('act: {}, config: {}'.format(act, data))
        if act == 'open':
            # if not os.path.exists('/var/run/clamd.amavisd/clamd.pid'):
            #     return public.returnMsg(False, 'clamd服务未开启，请先开启服务！')
            new_data = r'''#open_clamd
  ['ClamAV-clamd',
    \&ask_daemon, ["CONTSCAN {}\n", "/run/clamd.amavisd/clamd.sock"],
    qr/\bOK$/m, qr/\bFOUND$/m,
    qr/^.*?: (?!Infected Archive)(.*) FOUND$/m ],
#end_clamd'''
        elif act == 'close':
            new_data = '#open_clamd\n#end_clamd'
        else:
            return public.returnMsg(False, 'Unsupported operation!')
        public.writeFile('/etc/amavisd/amavisd.conf', config.replace(data, new_data))
        if os.path.exists('/etc/redhat-release'):
            public.ExecShell('systemctl restart amavisd')
        else:
            public.ExecShell('systemctl restart amavis')
        return public.returnMsg(True, 'Set up successfully!')

    def get_clamd_switch_status(self, get):
        '''
        获取amavisd配置中的clamd状态是否开启
        :param get:
        :return:
        '''
        import re

        config = public.readFile('/etc/amavisd/amavisd.conf')
        try:
            data = re.findall('#open_clamd(.+)#end_clamd', config, re.S)[0].strip()
            if data:
                return {'open': True}
            else:
                return {'open': False}
        except:
            return public.returnMsg(False, 'No corresponding configuration found')