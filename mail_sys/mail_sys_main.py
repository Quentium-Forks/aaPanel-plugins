#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: wzjie <wzj@bt.cn>
# | Author: zhwen <zhw@bt.cn>
# +-------------------------------------------------------------------

# +--------------------------------------------------------------------
# |   宝塔邮局
# +--------------------------------------------------------------------

import binascii, base64, re, json, os, sys, time, shutil, socket
from genericpath import isfile
from datetime import datetime

if sys.version_info[0] == 3:
    from importlib import reload

if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')

sys.path.append("class/")
import public
import mail_server_init as msi

try:
    import dns.resolver
except:
    if os.path.exists('/www/server/panel/pyenv'):
        public.ExecShell('/www/server/panel/pyenv/bin/pip install dnspython')
    else:
        public.ExecShell('pip install dnspython')
    import dns.resolver

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email.encoders import encode_base64
from email.utils import COMMASPACE, formatdate, formataddr
from email.header import Header


class SendMail:
    '''
    发件类
    '''

    def __init__(self, username, password, server, port=25, usettls=False):
        self.mailUser = username
        self.mailPassword = password
        self.smtpServer = server
        self.smtpPort = port
        self.mailServer = smtplib.SMTP(self.smtpServer, self.smtpPort)
        if usettls:
            self.mailServer.starttls()
        self.mailServer.ehlo()
        self.mailServer.login(self.mailUser, self.mailPassword)
        self.msg = MIMEMultipart()

    def __del__(self):
        self.mailServer.close()

    def setMailInfo(self, name, subject, text, text_type, attachmentFilePaths):
        # self.msg['From'] = self.mailUser
        self.msg['From'] = formataddr([name, self.mailUser])
        self.msg['Date'] = formatdate(localtime=True)
        self.msg['Subject'] = subject

        self.msg.attach(MIMEText(text, text_type, _charset="utf-8"))
        for attachmentFilePath in attachmentFilePaths:
            self.msg.attach(self.addAttachmentFromFile(attachmentFilePath))

    # 添加附件从网络数据流
    def addAttachment(self, filename, filedata):
        part = MIMEBase('application', "octet-stream")
        part.set_payload(filedata)
        encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % str(Header(filename, 'utf8')))
        self.msg.attach(part)

    # 添加附件从本地文件路径
    def addAttachmentFromFile(self, attachmentFilePath):
        part = MIMEBase('application', "octet-stream")
        part.set_payload(open(attachmentFilePath, "rb").read())
        encode_base64(part)
        part.add_header('Content-Disposition', 'attachment; filename="%s"' % str(Header(attachmentFilePath, 'utf8')))
        return part

    def sendMail(self, receiveUsers):
        self.msg['To'] = COMMASPACE.join(receiveUsers)

        try:
            self.mailServer.sendmail(self.mailUser, receiveUsers, self.msg.as_string())
            # 保存邮件到发件箱
            local_part, domain = self.mailUser.split('@')
            dir_path = '/www/vmail/{0}/{1}/.Sent/cur'.format(domain, local_part)
            if not os.path.isdir(dir_path):
                os.makedirs(dir_path)
            file_name = public.GetRandomString(36)
            if file_name in [item.split(':')[0] for item in os.listdir(dir_path)]:
                file_name = public.GetRandomString(54)
            public.writeFile(os.path.join(dir_path, file_name), self.msg.as_string())
            os.system('chown -R vmail:mail /www/vmail')
            return public.returnMsg(True, 'Email sent successfully')
        except Exception as e:
            return public.returnMsg(False, 'Failed to send mail, error reason[{0}]'.format(str(e)))


class mail_sys_main:
    __setupPath = '/www/server/panel/plugin/mail_sys'
    _session_conf = __setupPath + '/session.json'
    _forward_conf = __setupPath + '/forward.json'
    _save_conf = __setupPath + '/save_day.json'
    postfix_main_cf = "/etc/postfix/main.cf"
    _check_time = 86400

    def __init__(self):
        # self.sys_v = system.system().GetSystemVersion().replace(' ', '').lower()
        self.sys_v = public.get_linux_distribution().lower()
        self._session = self._get_session()

        create_table_str = self.M('sqlite_master').where('type=? AND name=?', ('table', 'domain')).getField('sql')
        if create_table_str and 'a_record' not in create_table_str:
            self.M('domain').execute('ALTER TABLE `domain` ADD COLUMN `a_record` Text default "";')

    def get_postconf(self):
        if os.path.exists("/usr/sbin/postconf"):
            return "/usr/sbin/postconf"
        elif os.path.exists("/sbin/postconf"):
            return "/sbin/postconf"
        else:
            return "postconf"

    def check_mail_sys(self, args):
        if os.path.exists('/etc/postfix/sqlite_virtual_domains_maps.cf'):
            public.ExecShell('{} -e "message_size_limit = 102400000"'.format(self.get_postconf()))
            # 修改postfix mydestination配置项
            result = public.readFile(self.postfix_main_cf)
            if not result:
                return public.returnMsg(False, "No postfix configuration file found")
            result = re.search(r"\n*mydestination\s*=(.+)", result)
            if not result:
                return public.returnMsg(False,
                                        "The postfix configuration file did not find the mydestination parameter")
            result = result.group(1)
            if 'localhost' in result or '$myhostname' in result or '$mydomain' in result:
                public.ExecShell('{} -e "mydestination =" && systemctl restart postfix'.format(self.get_postconf()))
            # 修改dovecot配置
            dovecot_conf = public.readFile("/etc/dovecot/dovecot.conf")
            if not dovecot_conf or not re.search(r"\n*protocol\s*imap", dovecot_conf):
                return public.returnMsg(False, 'Failed to configure dovecot')
            # 修复之前版本未安装opendkim的问题
            # if not (os.path.exists("/usr/sbin/opendkim") and os.path.exists("/etc/opendkim.conf") and os.path.exists("/etc/opendkim")):
            #     if not self.setup_opendkim():
            #         return public.returnMsg(False, 'Failed to configure opendkim 1')

            return public.returnMsg(True, 'MAIL_SERVER_EXIST')
        else:
            return public.returnMsg(False, 'NOT_INSTALL_MAIL_SERVER')

    def check_mail_env(self, args):
        return msi.mail_server_init().check_env()

    def change_to_rspamd(self, args):
        msi.change_to_rspamd().main()
        return public.returnMsg(True,"Setup successfully")

    def install_rspamd(self, args):
        a, e = public.ExecShell("bash {}/install.sh rspamd".format(self.__setupPath))
        return public.returnMsg(True,"Install successfully")

    # 安装并配置postfix, dovecot
    def setup_mail_sys(self, args):
        '''
        安装邮局系统主函数
        :param args:
        :return:
        '''
        return msi.mail_server_init().setup_mail_sys(args)

    def _check_smtp_port(self):
        import telnetlib

        host_list = ['mx1.qq.com', 'mx2.qq.com', 'mx3.qq.com', 'smtp.gmail.com']
        for host in host_list:
            try:
                tn = telnetlib.Telnet(host, 25, timeout=1)
                if tn: return True
            except:
                continue
        return False

    # 获取公网ip
    def _get_pubilc_ip(self):
        import requests

        try:
            #url = 'http://pv.sohu.com/cityjson?ie=utf-8'
            url = 'https://ifconfig.me/ip'
            opener = requests.get(url)
            m_str = opener.text
            ip_address = re.search(r'\d+.\d+.\d+.\d+', m_str).group(0)
            c_ip = public.check_ip(ip_address)
            if not c_ip:
                a, e = public.ExecShell("curl ifconfig.me")
                return a
            return ip_address
        except:
            filename = '/www/server/panel/data/iplist.txt'
            ip_address = public.readFile(filename).strip()
            if public.check_ip(ip_address):
                return ip_address
            else:
                return None

    def _check_a(self, hostname):
        '''
        检测主机名是否有A记录
        :param hostname:
        :return:
        '''
        ipaddress = self._get_all_ip()
        if not ipaddress: return False
        key = '{0}:{1}'.format(hostname, 'A')
        now = int(time.time())
        value = ""
        error_ip = ""
        try:
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if not value:
                # result = model.resolver.query(hostname, 'A')
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                try:
                    result = resolver.query(hostname, 'A')
                except:
                    result = resolver.resolve(hostname, 'A')
                for i in result.response.answer:
                    for j in i.items:
                        error_ip = j
                        if str(j).strip() in ipaddress:
                            value = str(j).strip()
            if value:
                self._session[key] = {
                    "status": 1,
                    "v_time": now,
                    "value": value
                }
                return True
            if str(type(error_ip)).find("dns.rdtypes.IN.A") != -1:
                self._session[key] = {
                    "status": 0,
                    "v_time": now,
                    "value": error_ip.to_text()
                }
            else:
                self._session[key] = {
                    "status": 0,
                    "v_time": now,
                    "value": error_ip
                }
            return False
        except:
            print(public.get_error_info())
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False

    def repair_postfix(self, args=None):
        if self.sys_v == 'centos7':
            msi.mail_server_init().install_postfix_on_centos7()
        elif self.sys_v == 'centos8':
            msi.mail_server_init().install_postfix_on_centos8()
        elif self.sys_v == 'ubuntu':
            msi.mail_server_init().install_postfix_on_ubuntu()
        return msi.mail_server_init().conf_postfix()

    def repair_dovecot(self, args=None):
        status = False
        if os.path.exists('/etc/dovecot/conf.d/10-ssl.conf'):
            if os.path.exists('/tmp/10-ssl.conf_aap_bak'):
                os.remove('/tmp/10-ssl.conf_aap_bak')
            shutil.move('/etc/dovecot/conf.d/10-ssl.conf', '/tmp/10-ssl.conf_aap_bak')
        if self.sys_v == 'centos7':
            if msi.mail_server_init().install_dovecot_on_centos7():
                status = True
        elif self.sys_v == 'centos8':
            msi.mail_server_init().install_postfix_on_centos8()
            status = True
        elif self.sys_v == 'ubuntu':
            msi.mail_server_init().install_dovecot_on_ubuntu()
            status = True
        if os.path.exists('/tmp/10-ssl.conf_aap_bak') and os.path.exists('/etc/dovecot/conf.d'):
            if os.path.exists("/etc/dovecot/conf.d/10-ssl.conf"):
                os.remove('/etc/dovecot/conf.d/10-ssl.conf')
            shutil.move('/tmp/10-ssl.conf_aap_bak', '/etc/dovecot/conf.d/10-ssl.conf')
        return public.returnMsg(status,"Repair {}！".format("Successfully" if status else "Fail"))

    # 修复服务配置文件不全的问题
    def repair_service_conf(self, args=None):
        service_name = args.service
        if service_name.lower() not in ['postfix', 'dovecot', 'rspamd']:
            return public.returnMsg(False, 'Service name not exist')
        if service_name == 'postfix':
            self.repair_postfix()
        elif service_name == 'dovecot':
            self.repair_dovecot()
        elif service_name == 'rspamd':
            msi.mail_server_init().setup_rspamd()
        return public.returnMsg(True, 'Repair Complete')

    # 获取服务状态
    def get_service_status(self, args=None):
        data = {}
        data['change_rspamd'] = True if "smtpd_milters = inet:127.0.0.1:11332" not in public.readFile(
            "/etc/postfix/main.cf") else False
        data['postfix'] = public.process_exists('master', '/usr/libexec/postfix/master')
        data['dovecot'] = public.process_exists('dovecot', '/usr/sbin/dovecot')
        data['rspamd'] = public.process_exists('rspamd', '/usr/bin/rspamd')
        data['opendkim'] = public.process_exists('opendkim', '/usr/sbin/opendkim')
        if "ubuntu" in self.sys_v:
            data['postfix'] = public.process_exists('master', '/usr/lib/postfix/sbin/master')
        return data

    def get_mail_log(self, args):
        path = '/var/log/maillog'
        if "ubuntu" in self.sys_v:
            path = '/var/log/mail.log'
        if not os.path.exists(path): return {'log': 'Log file does not exist'}
        text = public.GetNumLines(path, 500)
        return {'log': text}

    def M(self, table_name):
        import db
        sql = db.Sql()
        sql._Sql__DB_FILE = '/www/vmail/postfixadmin.db'
        sql._Sql__encrypt_keys = []
        return sql.table(table_name)

    def flush_domain_record(self, args):
        '''
        手动刷新域名记录
        domain all/specify.com
        :param args:
        :return:
        '''
        if args.domain == 'all':
            data_list = self.M('domain').order('created desc').field('domain,a_record,created,active').select()
            for item in data_list:
                try:
                    if os.path.exists("/usr/bin/rspamd"):
                        self.set_rspamd_dkim_key(item['domain'])
                    if os.path.exists("/usr/sbin/opendkim"):
                        self._gen_dkim_key(item['domain'])
                except:
                    return public.returnMsg(False, 'Please check if the rspamd service is running')
                self._gevent_jobs(item['domain'], item['a_record'])
        else:
            try:
                if os.path.exists("/usr/bin/rspamd"):
                    self.set_rspamd_dkim_key(args.domain)
                if os.path.exists("/usr/sbin/opendkim"):
                    self._gen_dkim_key(args.domain)
            except:
                return public.returnMsg(False, 'Please check if the rspamd service is running')
            try:
                self._gevent_jobs(args.domain, None)  # 不需要验证A记录
            except:
                public.print_log('error:{}'.format(str(public.get_error_info())))
        try:
            public.writeFile(self._session_conf, json.dumps(self._session))
            return public.returnMsg(True, 'Flush successfully')

        except:
            # public.print_log('error:{}'.format(str(public.get_error_info())))
            return public.returnMsg(False, 'Flush successfully')

    def get_record_in_cache(self, item):
        try:
            item['mx_status'] = self._session['{0}:{1}'.format(item['domain'], 'MX')]["status"]
            item['spf_status'] = self._session['{0}:{1}'.format(item['domain'], 'TXT')]["status"]
            item['dkim_status'] = self._session['{0}:{1}'.format("default._domainkey." + item['domain'], 'TXT')][
                "status"]
            item['dmarc_status'] = self._session['{0}:{1}'.format("_dmarc." + item['domain'], 'TXT')]["status"]
            item['a_status'] = self._session['{0}:{1}'.format(item['a_record'], 'A')]["status"]
        except:
            self._gevent_jobs(item['domain'], item['a_record'])
            self.get_record_in_cache(item)
        return item

    def get_domains(self, args):
        '''
        域名查询接口
        :param args:
        :return:
        '''
        p = int(args.p) if 'p' in args else 1
        rows = int(args.size) if 'size' in args else 10
        callback = args.callback if 'callback' in args else ''
        count = self.M('domain').count()

        # 获取分页数据
        page_data = public.get_page(count, p=p, rows=rows, callback=callback)

        # 获取当前页的数据列表
        data_list = self.M('domain').order('created desc').limit(page_data['shift'] + ',' + page_data['row']).field(
            'domain,a_record,created,active').select()
        for item in data_list:
            try:
                if os.path.exists("/usr/bin/rspamd"):
                    self.set_rspamd_dkim_key(item['domain'])
                if os.path.exists("/usr/sbin/opendkim"):
                    self._gen_dkim_key(item['domain'])
            except:
                return public.returnMsg(False, 'Please check if the rspamd service is running')
            if not os.path.exists(self._session_conf):
                self._gevent_jobs(item['domain'], item['a_record'])
                item = self.get_record_in_cache(item)
            else:
                item = self.get_record_in_cache(item)
            item['dkim_value'] = self._get_dkim_value(item['domain'])
            item['dmarc_value'] = 'v=DMARC1;p=quarantine;rua=mailto:admin@{0}'.format(item['domain'])
            item['mx_record'] = item['a_record']
            item['ssl_status'] = self._get_multiple_certificate_domain_status(item['domain'])
            item['catch_all'] = self._get_catchall_status(item['domain'])
            item['ssl_info'] = self.get_ssl_info(item['domain'])

        public.writeFile(self._session_conf, json.dumps(self._session))
        # 返回数据到前端
        return public.returnMsg(True, {'data': data_list, 'page': page_data['page']})

    def _gevent_jobs(self, domain, a_record):
        from gevent import monkey
        monkey.patch_all()
        import gevent
        gevent.joinall([
            gevent.spawn(self._check_mx, domain),
            gevent.spawn(self._check_spf, domain),
            gevent.spawn(self._check_dkim, domain),
            gevent.spawn(self._check_dmarc, domain),
            gevent.spawn(self._check_a, a_record),
        ])
        return True

    def _build_dkim_sign_content(self, domain, dkim_path):
        dkim_signing_conf = """#{domain}_DKIM_BEGIN
  {domain} {{
    selectors [
     {{
       path: "{dkim_path}/default.private";
       selector: "default"
     }}
   ]
 }}
#{domain}_DKIM_END
""".format(domain=domain, dkim_path=dkim_path)
        return dkim_signing_conf

    def _dkim_sign(self, domain, dkim_sign_content):
        res = self.check_domain_in_rspamd_dkim_conf(domain)
        if not res:
            return False
        sign_domain = '#BT_DOMAIN_DKIM_BEGIN{}#BT_DOMAIN_DKIM_END'.format(res['sign_domain'].group(1) + dkim_sign_content)
        sign_conf = re.sub(res['rep'], sign_domain, res['sign_conf'])
        public.writeFile(res['sign_path'], sign_conf)
        return True

    def check_domain_in_rspamd_dkim_conf(self,domain):
        sign_path = '/etc/rspamd/local.d/dkim_signing.conf'
        sign_conf = public.readFile(sign_path)
        if not sign_conf:
            public.writeFile(sign_conf,"#BT_DOMAIN_DKIM_BEGIN\n#BT_DOMAIN_DKIM_END")
            sign_conf = """
domain {
#BT_DOMAIN_DKIM_BEGIN
#BT_DOMAIN_DKIM_END
}
            """
        rep = '#BT_DOMAIN_DKIM_BEGIN((.|\n)+)#BT_DOMAIN_DKIM_END'
        sign_domain = re.search(rep, sign_conf)
        if not sign_domain:
            return False
        if domain in sign_domain.group(1):
            return False
        return {"rep":rep,"sign_domain":sign_domain,'sign_conf':sign_conf,'sign_path':sign_path}

    def set_rspamd_dkim_key(self, domain):
        dkim_path = '/www/server/dkim/{}'.format(domain)
        if not dkim_path:
            os.makedirs(dkim_path)
        if not os.path.exists('{}/default.pub'.format(dkim_path)):
            dkim_shell = """
    mkdir -p {dkim_path}
    rspamadm dkim_keygen -s 'default' -b 1024 -d {domain} -k /www/server/dkim/{domain}/default.private > /www/server/dkim/{domain}/default.pub
    chmod 755 -R /www/server/dkim/{domain}
    """.format(dkim_path=dkim_path, domain=domain)
            public.ExecShell(dkim_shell)
        dkim_sign_content = self._build_dkim_sign_content(domain, dkim_path)
        if self._dkim_sign(domain, dkim_sign_content):
            public.ExecShell('systemctl reload rspamd')
        return True

    def _gen_dkim_key(self, domain):
        if not os.path.exists('/usr/share/perl5/vendor_perl/Getopt/Long.pm'):
            os.makedirs('/usr/share/perl5/vendor_perl/Getopt')
            public.ExecShell(
                'wget -O /usr/share/perl5/vendor_perl/Getopt/Long.pm {}/install/plugin/mail_sys/Long.pm -T 10'
                .format(public.get_url()))
        if not os.path.exists('/etc/opendkim/keys/{0}/default.private'.format(domain)):
            dkim_shell = '''
mkdir /etc/opendkim/keys/{domain}
opendkim-genkey -D /etc/opendkim/keys/{domain}/ -d {domain} -s default -b 1024
chown -R opendkim:opendkim /etc/opendkim/
systemctl restart  opendkim'''.format(domain=domain)
            keytable = "default._domainkey.{domain} {domain}:default:/etc/opendkim/keys/{domain}/default.private".format(
                domain=domain)
            sigingtable = "*@{domain} default._domainkey.{domain}".format(domain=domain)
            keytable_conf = public.readFile("/etc/opendkim/KeyTable")
            sigingtable_conf = public.readFile("/etc/opendkim/SigningTable")
            if keytable_conf:
                if keytable not in keytable_conf:
                    keytable_conf = keytable_conf + keytable + "\n"
                    public.writeFile("/etc/opendkim/KeyTable", keytable_conf)
            if sigingtable_conf:
                if sigingtable not in sigingtable_conf:
                    sigingtable_conf = sigingtable_conf + sigingtable + "\n"
                    public.writeFile("/etc/opendkim/SigningTable", sigingtable_conf)
            public.ExecShell(dkim_shell)

    def _get_dkim_value(self, domain):
        '''
        解析/etc/opendkim/keys/domain/default.txt得到域名要设置的dkim记录值
        :param domain:
        :return:
        '''
        if not os.path.exists("/www/server/dkim/{}".format(domain)):
            os.makedirs("/www/server/dkim/{}".format(domain))
        rspamd_pub_file = '/www/server/dkim/{}/default.pub'.format(domain)
        opendkim_pub_file = '/etc/opendkim/keys/{0}/default.txt'.format(domain)
        if os.path.exists(opendkim_pub_file) and not os.path.exists(rspamd_pub_file):
            opendkim_pub = public.readFile(opendkim_pub_file)
            public.writeFile(rspamd_pub_file, opendkim_pub)

            rspamd_pri_file = '/www/server/dkim/{}/default.private'.format(domain)
            opendkim_pri_file = '/etc/opendkim/keys/{}/default.private'.format(domain)
            opendkim_pri = public.readFile(opendkim_pri_file)
            public.writeFile(rspamd_pri_file, opendkim_pri)

        if not os.path.exists(rspamd_pub_file): return ''
        file_body = public.readFile(rspamd_pub_file).replace(' ', '').replace('\n', '').split('"')
        value = file_body[1] + file_body[3]
        return value

    def _get_session(self):
        session = public.readFile(self._session_conf)
        if session:
            session = json.loads(session)
        else:
            session = {}
        return session

    def _check_mx(self, domain):
        '''
        检测域名是否有mx记录
        :param domain:
        :return:
        '''
        a_record = self.M('domain').where('domain=?', domain).field('a_record').find()['a_record']
        key = '{0}:{1}'.format(domain, 'MX')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                try:
                    result = resolver.query(domain, 'MX')
                except:
                    result = resolver.resolve(domain, 'MX')
                value = str(result[0].exchange).strip('.')
            if not a_record:
                a_record = value
                self.M('domain').where('domain=?', domain).save('a_record', (a_record,))
            if value == a_record:
                self._session[key] = {"status": 1, "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            print(public.get_error_info())
            self._session[key] = {"status": 0, "v_time": now,
                                  "value": "None of DNS query names exist:{}".format(domain)}
            return False

    def _check_spf(self, domain):
        '''
        检测域名是否有spf记录
        :param domain:
        :return:
        '''
        key = '{0}:{1}'.format(domain, 'TXT')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                try:
                    result = resolver.query(domain, 'TXT')
                except:
                    result = resolver.resolve(domain, 'TXT')
                for i in result.response.answer:
                    for j in i.items:
                        value += str(j).strip()
            if 'v=spf1' in value.lower():
                self._session[key] = {"status": 1, "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            print(public.get_error_info())
            self._session[key] = {"status": 0, "v_time": now, "value": "None of DNS query spf exist:{}".format(domain)}
            return False

    def _check_dkim(self, domain):
        '''
        检测域名是否有dkim记录
        :param domain:
        :return:
        '''
        origin_domain = domain
        domain = 'default._domainkey.{0}'.format(domain)
        key = '{0}:{1}'.format(domain, 'TXT')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                # result = model.resolver.query(domain, 'TXT')
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                try:
                    result = resolver.query(domain, 'TXT')
                except:
                    result = resolver.resolve(domain, 'TXT')
                for i in result.response.answer:
                    for j in i.items:
                        value += str(j).strip()
            new_v = self._get_dkim_value(origin_domain)
            if new_v and new_v in value:
                self._session[key] = {"status": 1, "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            print(public.get_error_info())
            self._session[key] = {"status": 0, "v_time": now,
                                  "value": "None of DNS query names exist:{}".format(domain)}
            return False

    def _check_dmarc(self, domain):
        '''
        检测域名是否有dmarc记录
        :param domain:
        :return:
        '''
        domain = '_dmarc.{0}'.format(domain)
        key = '{0}:{1}'.format(domain, 'TXT')
        now = int(time.time())
        try:
            value = ""
            if key in self._session and self._session[key]["status"] != 0:
                v_time = now - int(self._session[key]["v_time"])
                if v_time < self._check_time:
                    value = self._session[key]["value"]
            if '' == value:
                # result = model.resolver.query(domain, 'TXT')
                resolver = dns.resolver.Resolver()
                resolver.timeout = 1
                try:
                    result = resolver.query(domain, 'TXT')
                except:
                    result = resolver.resolve(domain, 'TXT')
                for i in result.response.answer:
                    for j in i.items:
                        value += str(j).strip()
            if 'v=dmarc1' in value.lower():
                self._session[key] = {"status": 1, "v_time": now, "value": value}
                return True
            self._session[key] = {"status": 0, "v_time": now, "value": value}
            return False
        except:
            print(public.get_error_info())
            self._session[key] = {"status": 0, "v_time": now,
                                  "value": "None of DNS query names exist:{}".format(domain)}
            return False

    def get_mx_txt_cache(self, args):
        session = self._get_session()
        if 'domain' not in args:
            return public.returnMsg(False, 'DOMAIN_NAME')
        domain = args.domain

        mx_key = '{0}:{1}'.format(domain, 'MX')
        spf_key = '{0}:{1}'.format(domain, 'TXT')
        dkim_key = '{0}:{1}'.format('default._domainkey.{0}'.format(domain), 'TXT')
        dmarc_key = '{0}:{1}'.format('_dmarc.{0}'.format(domain), 'TXT')

        mx_value = session[mx_key] if mx_key in session else ''
        spf_value = session[spf_key] if spf_key in session else ''
        dkim_value = session[dkim_key] if dkim_key in session else ''
        dmarc_value = session[dmarc_key] if dmarc_key in session else ''

        return {'mx': mx_value, 'spf': spf_value, 'dkim': dkim_value, 'dmarc': dmarc_value}

    def delete_mx_txt_cache(self, args):
        session = self._get_session()
        if 'domain' not in args:
            return public.returnMsg(False, 'DOMAIN_NAME')
        domain = args.domain

        mx_key = '{0}:{1}'.format(domain, 'MX')
        spf_key = '{0}:{1}'.format(domain, 'TXT')
        dkim_key = '{0}:{1}'.format('default._domainkey.{0}'.format(domain), 'TXT')
        dmarc_key = '{0}:{1}'.format('_dmarc.{0}'.format(domain), 'TXT')

        if mx_key in session: del (session[mx_key])
        if spf_key in session: del (session[spf_key])
        if dkim_key in session: del (session[dkim_key])
        if dmarc_key in session: del (session[dmarc_key])
        public.writeFile(self._session_conf, json.dumps(session))

        return public.returnMsg(True, public.GetMsg("DELETE_DOMAIN_CACHE", (domain,)))

    def add_domain(self, args):
        '''
        域名增加接口
        :param args:
        :return:
        '''
        if 'domain' not in args:
            return public.returnMsg(False, 'DOMAIN_NAME')
        domain = args.domain
        a_record = args.a_record
        if not a_record.endswith(domain):
            return public.returnMsg(False, 'A record [{}] does not belong to the domain name'.format(a_record))
        if not self._check_a(a_record):
            return public.returnMsg(False, 'A record parsing failed <br>Doamin: {}<br>IP: {}'.format(a_record,self._session['{}:A'.format(a_record)]['value']))

        if self.M('domain').where('domain=?', domain).count() > 0:
            return public.returnMsg(False, 'The domain name already exists')

        cur_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        try:
            self.M('domain').add('domain,a_record,created', (domain, a_record, cur_time))
        except:
            return public.returnMsg(False, 'Mail server did not initialize successfully.<br>'
                                           'Please reopen the plugin to initialize,<br>'
                                           'If the server does not open <br>port 25 [outbound direction]<br>it cannot be initialized.<br> '
                                           'You can run:<br><br> [ telnet gmail-smtp-in.l.google.com 25 ] <br>in the terminal to check whether it is open.')

        # 在虚拟用户家目录创建对应域名的目录
        if not os.path.exists('/www/vmail/{0}'.format(domain)):
            os.makedirs('/www/vmail/{0}'.format(domain))
        public.ExecShell('chown -R vmail:mail /www/vmail/{0}'.format(domain))
        return public.returnMsg(True, 'Add domain [{0}] succeeded!'.format(domain))

    def edit_domain_record(self, args):
        if 'domain' not in args:
            return public.returnMsg(False, 'Please pass in the domain name')
        domain = args.domain
        a_record = args.a_record
        if self.M('domain').where('domain=?', domain).count() == 0:
            return public.returnMsg(False, 'The domain name does not exist')
        self.M('domain').where('domain=?', domain).save('a_record', (a_record,))
        return public.returnMsg(True, 'Modify the domain name [{0}] A record successfully!'.format(domain))

    def delete_domain(self, args):
        '''
        域名删除接口
        :param args:
        :return:
        '''
        if 'domain' not in args:
            return public.returnMsg(False, 'DOMAIN_NAME')
        domain = args.domain

        # 删除域名记录
        self.M('domain').where('domain=?', (domain,)).delete()
        # 删除域名下的邮箱记录
        self.M('mailbox').where('domain=?', (domain,)).delete()
        self.delete_mx_txt_cache(args)

        # 在虚拟用户家目录删除对应域名的目录
        public.ExecShell('rm -rf /www/vmail/{0}'.format(domain))
        return public.returnMsg(True, 'Deleting the domain successfully! ({0})'.format(domain))

    def create_mail_box(self, user, passwd):
        try:
            import imaplib
            conn = imaplib.IMAP4(port=143, host='127.0.0.1')
            conn.login(user, passwd)
            conn.select('Junk')
            conn.select('Trash')
            conn.select('Drafts')
            conn.close()
        except:
            return False

    def get_mailboxs(self, args):
        '''
        邮箱用户查询接口
        :param args:
        :return:
        '''
        p = int(args.p) if 'p' in args else 1
        rows = int(args.size) if 'size' in args else 12
        callback = args.callback if 'callback' in args else ''
        if 'domain' in args:
            domain = args.domain
            count = self.M('mailbox').where('domain=?', domain).count()
            # 获取分页数据
            page_data = public.get_page(count, p, rows, callback)
            # 获取当前页的数据列表
            data_list = self.M('mailbox').order('created desc').limit(
                page_data['shift'] + ',' + page_data['row']).where('domain=?', domain).field(
                'full_name,username,quota,created,modified,active,is_admin').select()
            # 返回数据到前端
            return {'data': data_list, 'page': page_data['page']}
        else:
            count = self.M('mailbox').count()
            # 获取分页数据
            page_data = public.get_page(count, p, rows, callback)
            # 获取当前页的数据列表
            data_list = self.M('mailbox').order('created desc').limit(
                page_data['shift'] + ',' + page_data['row']).field(
                'full_name,username,quota,created,modified,active,is_admin').select()
            # 返回数据到前端
            return {'data': data_list, 'page': page_data['page']}

    def get_all_user(self, args):
        if 'domain' in args:
            data_list = self.M('mailbox').where('domain=? AND active=?', (args.domain, 1)).field(
                'full_name,username,quota,created,modified,active,is_admin').select()
        else:
            data_list = self.M('mailbox').where('active=?', 1).field(
                'full_name,username,quota,created,modified,active,is_admin').select()
        return data_list

    # 加密数据
    def _encode(self, data):
        str2 = data.strip()
        if sys.version_info[0] == 2:
            b64_data = base64.b64encode(str2)
        else:
            b64_data = base64.b64encode(str2.encode('utf-8'))
        return binascii.hexlify(b64_data).decode()

    # 解密数据
    def _decode(self, data):
        b64_data = binascii.unhexlify(data.strip())
        return base64.b64decode(b64_data).decode()

    # 检测密码强度
    def _check_passwd(self, password):
        return True if re.search(r"^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).*$", password) and len(password) >= 8 else False

    def _check_email_address(self, email_address):
        return True if re.match(r"^\w+([.-]?\w+)*@.*", email_address) else False

    # 生成MD5-CRYPT模式加密的密码
    def _generate_crypt_passwd(self, password):
        if sys.version_info[0] == 2:
            shell_str = 'doveadm pw -s MD5-CRYPT -p {0}'.format(password)
            return public.ExecShell(shell_str)[0][11:].strip()
        else:
            import crypt
            return crypt.crypt(password, crypt.mksalt(crypt.METHOD_MD5))

    # 批量创建邮箱
    def __create_mail_box_mulitiple(self, info, args):
        create_successfully = {}
        create_failed = {}
        # status = False
        for data in info:
            if not data:
                continue
            try:
                args.quota = '{} {}'.format(data['quota'],data['unit'])
                args.username = data['username']
                args.password = data['password']
                args.full_name = data['full_name']
                args.is_admin = 0
                result = self.add_mailbox(args)
                if result['status']:
                    create_successfully[data['username']] = result['msg']
                    continue
                # create_successfully[data['username']] = create_other
                create_failed[data['username']] = result['msg']
            except:
                create_failed[data['username']] = "create error"
        # if not create_failed:
        #     status = True
        return {'status': True, 'msg': "Create the mailbox [ {} ] successfully".format(','.join(create_successfully)),
                'error': create_failed,
                'success': create_successfully}

    # 批量创建邮箱
    def add_mailbox_multiple(self, args):
        '''
            @name 批量创建网站
            @author zhwen<2020-11-26>
            @param create_type txt  txt格式为 “Name|Address|Password|MailBox space|GB” 每个网站一行
                                                 "support|support|Password|5|GB"
            @param content     "["support|support|Password|5|GB"]"
        '''
        key = ['full_name', 'username', 'password', 'quota', 'unit']
        info = [dict(zip(key, i)) for i in
                         [i.strip().split('|') for i in json.loads(args.content)]]
        if not info:
            return public.returnMsg(False,'The param is empty, Insufficient password strength (need to include uppercase and lowercase letters and numbers and no less than 8 in length)')
        res = self.__create_mail_box_mulitiple(info, args)
        return res

    def add_mailbox(self, args):
        '''
        新增邮箱用户
        :param args:
        :return:
        '''
        if 'username' not in args:
            return public.returnMsg(False, 'ENTER_ACCOUNT_NAME')
        if not self._check_passwd(args.password):
            return public.returnMsg(False,
                                    'Insufficient password strength (need to include uppercase and lowercase letters and numbers and no less than 8 in length)')
        username = args.username
        if not self._check_email_address(username):
            return public.returnMsg(False, 'Email address format is incorrect')
        if not username.islower():
            return public.returnMsg(False, 'Email address cannot have uppercase letters!')
        is_admin = args.is_admin if 'is_admin' in args else 0

        # shell_str = 'doveadm pw -s MD5-CRYPT -p {0}'.format(args.password)
        # password_encrypt = public.ExecShell(shell_str)[0][11:].strip()
        password_encrypt = self._generate_crypt_passwd(args.password)
        password_encode = self._encode(args.password)
        local_part, domain = username.split('@')
        domain_list = [item['domain'] for item in self.M('domain').field('domain').select()]
        if domain not in domain_list:
            return public.returnMsg(False, 'The domain name is not in the MailServer {}'.format(domain))
        num, unit = args.quota.split()
        if unit == 'GB':
            quota = float(num) * 1024 * 1024 * 1024
        else:
            quota = float(num) * 1024 * 1024

        count = self.M('mailbox').where('username=?', (username,)).count()
        if count > 0:
            return public.returnMsg(False, 'EMAIL_EXIST')

        cur_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.M('mailbox').add(
            'full_name,is_admin,username,password,password_encode,maildir,quota,local_part,domain,created,modified',
            (args.full_name, is_admin, username, password_encrypt, password_encode, args.username + '/', quota,
             local_part, domain, cur_time, cur_time))

        # 在虚拟用户家目录创建对应邮箱的目录
        user_path = '/www/vmail/{0}/{1}'.format(domain, local_part)
        os.makedirs(user_path)
        os.makedirs(user_path + '/tmp')
        os.makedirs(user_path + '/new')
        os.makedirs(user_path + '/cur')
        public.ExecShell('chown -R vmail:mail /www/vmail/{0}/{1}'.format(domain, local_part))
        self.create_mail_box(username, args.password)
        return public.returnMsg(True, public.GetMsg("ADD_MAILUSER", (username,)))

    def update_mailbox(self, args):
        '''
        邮箱用户修改接口
        :param args:
        :return:
        '''
        num, unit = args.quota.split()
        if unit == 'GB':
            quota = float(num) * 1024 * 1024 * 1024
        else:
            quota = float(num) * 1024 * 1024
        cur_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if 'password' in args and args.password != '':
            if not self._check_passwd(args.password):
                return public.returnMsg(False,
                                        'Insufficient password strength (need to include uppercase and lowercase letters and numbers and no less than 8 in length)')
            # shell_str = 'doveadm pw -s MD5-CRYPT -p {0}'.format(args.password)
            # password_encrypt = public.ExecShell(shell_str)[0][11:].strip()
            password_encrypt = self._generate_crypt_passwd(args.password)
            password_encode = self._encode(args.password)
            self.M('mailbox').where('username=?', args.username).save(
                'password,password_encode,full_name,quota,modified,active,is_admin',
                (password_encrypt, password_encode, args.full_name, quota, cur_time, args.active, args.is_admin))
        else:
            self.M('mailbox').where('username=?', args.username).save('full_name,quota,modified,active,is_admin', (
            args.full_name, quota, cur_time, args.active, args.is_admin))
        return public.returnMsg(True, public.GetMsg("MODIFY_MAILUSER", (args.username,)))

    def delete_mailbox(self, args):
        '''
        删除邮箱用户
        :param args:
        :return:
        '''
        if 'username' not in args:
            return public.returnMsg(False, 'ENTER_ACCOUNT_NAME')
        username = args.username
        local_part, domain = username.split('@')
        res = self.M('mailbox').where('username=?', username).count()
        if not res:
            return public.returnMsg(False, "Delete Failed!")
        self.M('mailbox').where('username=?', username).delete()

        # 在虚拟用户家目录删除对应邮箱的目录
        if os.path.exists('/www/vmail/{0}/{1}'.format(domain, local_part)):
            public.ExecShell('rm -rf /www/vmail/{0}/{1}'.format(domain, local_part))
        return public.returnMsg(True, public.GetMsg("DEL_MAILUSER", (username,)))

    def send_mail(self, args):
        service_status = self.get_service_status(args)
        if not service_status['postfix']:
            return public.returnMsg(False,
                                    'Unable to send mail, error Cause: Some services are not started, please check the service status')
        if not self._check_smtp_port():
            return public.returnMsg(False,
                                    'Some cloud vendors (such as Google, Amazon) close port 25 by default, and you need to contact the vendor to open port 25 before you can use the post office service normally')

        mail_from = args.mail_from
        data = self.M('mailbox').where('username=?', mail_from).field('password_encode,full_name').find()
        password = self._decode(data['password_encode'])
        mail_to = json.loads(args.mail_to) if 'mail_to' in args else []
        for mail_address in mail_to:
            if not self._check_email_address(mail_address):
                return public.returnMsg(False,
                                        'Failed to send mail, error reason: Incoming address format is incorrect')
        subject = args.subject
        content = args.content
        subtype = args.subtype if 'subtype' in args else 'plain'
        if subtype.lower() not in ['plain', 'html']:
            return public.returnMsg(False, 'Incorrect message type')
        if subtype.lower() == 'html':
            content = '<html>' + content + '</html>'
        files = json.loads(args.files) if 'files' in args else []
        if not isinstance(mail_to, list):
            return public.returnMsg(False, 'RECIPIENT_LIST_ERR')
        if len(mail_to) == 0:
            return public.returnMsg(False, 'RECIPIENT_EMPTY_ERR')

        try:
            send_mail_client = SendMail(mail_from, password, 'localhost')
            send_mail_client.setMailInfo(data['full_name'], subject, content, subtype, files)
            result = send_mail_client.sendMail(mail_to)
            return result
        except Exception as e:
            print(public.get_error_info())
            return public.returnMsg(False, 'Failed to send mail, error reason [{0}]'.format(str(e)))

    def _check(self, args):
        if args['fun'] in ['send_mail_http']:
            return True
        else:
            return public.returnMsg(False, 'Interface does not support public access!')

    def send_mail_http(self, args):
        service_status = self.get_service_status(args)
        if not service_status['postfix']:
            return public.returnMsg(False,
                                    'Unable to send email, Reason: Some services are not started, please check the service status')
        if not self._check_smtp_port():
            return public.returnMsg(False,
                                    'Some cloud vendors (such as Google, Amazon) close port 25 by default, and you need to contact the vendor to open port 25 before you can use the post office service normally')

        mail_from = args.mail_from
        password = args.password
        mail_to = [item.strip() for item in args.mail_to.split(',')]
        for mail_address in mail_to:
            if not self._check_email_address(mail_address):
                return public.returnMsg(False,
                                        'Failed to send mail, error reason: Incoming address format is incorrect')
        subject = args.subject
        content = args.content
        subtype = args.subtype if 'subtype' in args else 'plain'
        if subtype.lower() not in ['plain', 'html']:
            return public.returnMsg(False, 'Incorrect message type')
        if subtype.lower() == 'html':
            content = '<html>' + content + '</html>'
        files = json.loads(args.files) if 'files' in args else []

        try:
            data = self.M('mailbox').where('username=?', mail_from).field('full_name').find()
            send_mail_client = SendMail(mail_from, password, 'localhost')
            send_mail_client.setMailInfo(data['full_name'], subject, content, subtype, files)
            result = send_mail_client.sendMail(mail_to)
            return result
        except Exception as e:
            print(public.get_error_info())
            return public.returnMsg(False, public.GetMsg("SENT_FAIL", (str(e),)))

    # 获取文件编码类型
    def get_encoding(self, file):
        import chardet

        try:
            # 二进制方式读取，获取字节数据，检测类型
            with open(file, 'rb') as f:
                data = f.read()
                return chardet.detect(data)['encoding']
        except:
            return 'ascii'

    def get_mails(self, args):
        import email
        import receive_mail
        reload(receive_mail)

        if 'username' not in args:
            return public.returnMsg(False, 'ENTER_ACCOUNT_NAME')
        username = args.username
        if '@' not in username:
            return public.returnMsg(False, 'ACCOUNT_NAME_ERR')
        local_part, domain = username.split('@')
        if 'p' not in args:
            args.p = 1
        if 'p=' in args.p:
            args.p = args.p.split('p=')[-1]

        receive_mail_client = receive_mail.ReceiveMail()
        mail_list = []
        try:
            dir_path = '/www/vmail/{0}/{1}/cur'.format(domain, local_part)
            if os.path.isdir(dir_path):
                # 先将new文件夹的邮件移动到cur文件夹
                new_path = '/www/vmail/{0}/{1}/new'.format(domain, local_part)
                if os.path.isdir(new_path):
                    for file in os.listdir(new_path):
                        src = os.path.join(new_path, file)
                        dst = os.path.join(dir_path, file)
                        shutil.move(src, dst)
                files = []
                for fname in os.listdir(dir_path):
                    mail_file = os.path.join(dir_path, fname)
                    if not os.path.exists(mail_file): continue
                    f_info = {}
                    f_info['name'] = fname
                    f_info['mtime'] = os.path.getmtime(mail_file)
                    save_day = self.get_save_day(None)
                    if save_day > 0:
                        deltime = int(time.time()) - save_day * 86400
                        if int(f_info['mtime']) < deltime:
                            os.remove(mail_file)
                            continue
                    files.append(f_info)
                files = sorted(files, key=lambda x: x['mtime'], reverse=True)
                page_data = public.get_page(len(files), int(args.p.split('?')[-1]), 10)
                shift = int(page_data['shift'])
                row = int(page_data['row'])
                files = files[shift:shift + row]
                for d in files:
                    mail_file = os.path.join(dir_path, d['name'])
                    encoding = self.get_encoding(mail_file)
                    print(encoding)
                    if sys.version_info[0] == 2:
                        import io
                        fp = io.open(mail_file, 'r', encoding=encoding)
                    else:
                        fp = open(mail_file, 'r', encoding=encoding)
                    try:
                        message = email.message_from_file(fp)
                        mailInfo = receive_mail_client.getMailInfo(msg=message)
                        mailInfo['path'] = mail_file
                        mail_list.append(mailInfo)
                    except:
                        public.writeFile("{}/error.log".format(self.__setupPath), public.get_error_info())
                        continue
                return {'status': True, 'data': mail_list,
                        'page': page_data['page'].replace('/plugin?action=a&name=mail_sys&s=get_mails&p=', '')}
            else:
                page_data = public.get_page(0, int(args.p), 10)
                return {'status': True, 'data': mail_list,
                        'page': page_data['page'].replace('/plugin?action=a&name=mail_sys&s=get_mails&p=', '')}
        except Exception as e:
            print(public.get_error_info())
            return public.returnMsg(False, 'Failed to get mail, error reason[{0}]'.format(str(e)))

    def delete_mail(self, args):
        path = args.path
        if not os.path.exists(path):
            return public.returnMsg(False, 'Mail path does not exist')
        os.remove(path)
        return public.returnMsg(True, 'Delete mail successfully')

    def get_config(self, args):
        from files import files

        if args.service == 'postfix':
            args.path = '/etc/postfix/main.cf'
        elif args.service == 'dovecot':
            args.path = '/etc/dovecot/dovecot.conf'
        elif args.service == 'rspamd':
            args.path = '/etc/rspamd/rspamd.conf'
        elif args.service == 'opendkim':
            args.path = '/etc/opendkim.conf'
        else:
            return public.returnMsg(False, 'Service name is incorrect')

        return files().GetFileBody(args)

    def save_config(self, args):
        from files import files

        if args.service == 'postfix':
            args.path = '/etc/postfix/main.cf'
        elif args.service == 'dovecot':
            args.path = '/etc/dovecot/dovecot.conf'
        elif args.service == 'rspamd':
            args.path = '/etc/rspamd/rspamd.conf'
        elif args.service == 'opendkim':
            args.path = '/etc/opendkim.conf'
        else:
            return public.returnMsg(False, 'Service name is incorrect')
        args.encoding = 'utf-8'

        result = files().SaveFileBody(args)
        if result['status']:
            if args.service == 'postfix':
                public.ExecShell('systemctl reload postfix')
            elif args.service == 'dovecot':
                public.ExecShell('systemctl reload dovecot')
            elif args.service == 'rspamd':
                public.ExecShell('systemctl reload rspamd')
            elif args.service == 'opendkim':
                public.ExecShell('systemctl reload opendkim')
        return result

    def service_admin(self, args):
        service_name = args.service
        if service_name.lower() not in ['postfix', 'dovecot', 'rspamd', 'opendkim']:
            return public.returnMsg(False, 'Service name is incorrect')
        type = args.type
        if type.lower() not in ['start', 'stop', 'restart', 'reload']:
            return public.returnMsg(False, 'Incorrect operation')

        exec_str = 'systemctl {0} {1}'.format(type, service_name)
        if type == 'reload':
            if service_name == 'postfix':
                exec_str = '/usr/sbin/postfix reload'
            elif service_name == 'dovecot':
                exec_str = '/usr/bin/doveadm reload'
            elif service_name == 'rspamd':
                exec_str = 'systemctl reload rspamd'
            elif service_name == 'opendkim':
                exec_str = 'systemctl reload opendkim'
        if service_name == 'opendkim' and type in ('start', 'restart'):
            exec_str = '''
sed -i "s#/var/run/opendkim/opendkim.pid#/run/opendkim/opendkim.pid#" /etc/opendkim.conf
sed -i "s#/var/run/opendkim/opendkim.pid#/run/opendkim/opendkim.pid#" /etc/sysconfig/opendkim
sed -i "s#/var/run/opendkim/opendkim.pid#/run/opendkim/opendkim.pid#" /usr/lib/systemd/system/opendkim.service
systemctl daemon-reload
systemctl enable opendkim
systemctl restart opendkim
'''

        public.ExecShell(exec_str)
        return public.returnMsg(True, '{0} Successful execution of {1} operation'.format(service_name, type))

    def get_sent_mails(self, args):
        import email
        import receive_mail
        reload(receive_mail)

        if 'username' not in args:
            return public.returnMsg(False, 'Please pass in the account name')
        username = args.username
        if '@' not in username:
            return public.returnMsg(False, 'The account name is invalid.')
        local_part, domain = username.split('@')
        if 'p' not in args:
            args.p = 1
        if 'p=' in args.p:
            args.p = args.p.split('p=')[-1]

        receive_mail_client = receive_mail.ReceiveMail()
        mail_list = []
        try:
            # 读取发件箱cur文件夹的邮件
            dir_path = '/www/vmail/{0}/{1}/.Sent/cur'.format(domain, local_part)
            if os.path.isdir(dir_path):
                files = []
                for fname in os.listdir(dir_path):
                    mail_file = os.path.join(dir_path, fname)
                    if not os.path.exists(mail_file): continue
                    f_info = {}
                    f_info['name'] = fname
                    f_info['mtime'] = os.path.getmtime(mail_file)
                    save_day = self.get_save_day(None)
                    if save_day > 0:
                        deltime = int(time.time()) - save_day * 86400
                        if int(f_info['mtime']) < deltime:
                            os.remove(mail_file)
                            continue
                    files.append(f_info)
                files = sorted(files, key=lambda x: x['mtime'], reverse=True)
                page_data = public.get_page(len(files), int(args.p), 10)
                shift = int(page_data['shift'])
                row = int(page_data['row'])
                files = files[shift:shift + row]
                for d in files:
                    mail_file = os.path.join(dir_path, d['name'])
                    fp = open(mail_file, 'r')
                    try:
                        message = email.message_from_file(fp)
                        mailInfo = receive_mail_client.getMailInfo(msg=message)
                        mailInfo['path'] = mail_file
                        mail_list.append(mailInfo)
                    except:
                        print(public.get_error_info())
                        continue
                return {'status': True, 'data': mail_list,
                        'page': page_data['page'].replace('/plugin?action=a&name=mail_sys&s=get_sent_mails&p=', '')}
            else:
                page_data = public.get_page(0, int(args.p), 10)
                return {'status': True, 'data': mail_list,
                        'page': page_data['page'].replace('/plugin?action=a&name=mail_sys&s=get_sent_mails&p=', '')}
        except Exception as e:
            print(public.get_error_info())
            return public.returnMsg(False, 'Failed to get sent mail, error reason [{0}]'.format(str(e)))

    # 设置postfix ssl
    def set_postfix_ssl(self, csrpath, keypath, act):
        main_file = self.postfix_main_cf
        master_file = "/etc/postfix/master.cf"
        main_conf = public.readFile(main_file)
        master_conf = public.readFile(master_file)
        if act == "0":
            csrpath = "/etc/pki/dovecot/certs/dovecot.pem"
            keypath = "/etc/pki/dovecot/private/dovecot.pem"
            master_rep = r"\n*\s*-o\s+smtpd_tls_auth_only=yes"
            master_str = "\n#  -o smtpd_tls_auth_only=yes"
            master_rep1 = r"\n*\s*-o\s+smtpd_tls_wrappermode=yes"
            master_str1 = "\n#  -o smtpd_tls_wrappermode=yes"
        else:
            master_rep = r"\n*#\s*-o\s+smtpd_tls_auth_only=yes"
            master_str = "\n  -o smtpd_tls_auth_only=yes"
            master_rep1 = r"\n*#\s*-o\s+smtpd_tls_wrappermode=yes"
            master_str1 = "\n  -o smtpd_tls_wrappermode=yes"

        for i in [[main_conf, main_file], [master_conf, master_file]]:
            if not i[0]:
                return public.returnMsg(False, "Can not find postfix config file {}".format(i[1]))
        main_rep = r"smtpd_tls_cert_file\s*=\s*.+"
        main_conf = re.sub(main_rep, "smtpd_tls_cert_file = {}".format(csrpath), main_conf)
        main_rep = r"smtpd_tls_key_file\s*=\s*.+"
        main_conf = re.sub(main_rep, "smtpd_tls_key_file = {}".format(keypath), main_conf)
        public.writeFile(main_file, main_conf)
        # master_rep = "#\s*-o\s+smtpd_tls_auth_only=yes"
        master_conf = re.sub(master_rep, master_str, master_conf)
        master_conf = re.sub(master_rep1, master_str1, master_conf)
        public.writeFile(master_file, master_conf)

    def get_dovecot_version(self, args=None):
        data = public.ExecShell("dpkg -l|grep dovecot-core|awk -F':' '{print $2}'")[0]
        if os.path.exists('/etc/redhat-release'):
            data = public.ExecShell('rpm -qa | grep dovecot | grep -v pigeonhole')[0].split('-')[1]
        return data

    def set_dovecot_ssl(self, csrpath, keypath, act):
        dovecot_version = self.get_dovecot_version()
        ssl_file = "/etc/dovecot/conf.d/10-ssl.conf"
        ssl_conf = public.readFile(ssl_file)
        if not ssl_conf:
            return public.returnMsg(False, "Can not find postfix config file {}".format(ssl_file))
        if act == "0":
            csrpath = "/etc/pki/dovecot/certs/dovecot.pem"
            keypath = "/etc/pki/dovecot/private/dovecot.pem"
        ssl_rep = r"ssl_cert\s*=\s*<.+"
        ssl_conf = re.sub(ssl_rep, "ssl_cert = <{}".format(csrpath), ssl_conf)
        ssl_rep = r"ssl_key\s*=\s*<.+"
        ssl_conf = re.sub(ssl_rep, "ssl_key = <{}".format(keypath), ssl_conf)
        if dovecot_version.startswith('2.3'):
            if act == '1':
                if not os.path.exists('/etc/dovecot/dh.pem') or os.path.getsize('/etc/dovecot/dh.pem') < 300:
                    public.ExecShell('openssl dhparam 2048 > /etc/dovecot/dh.pem')
                ssl_conf = ssl_conf + "\nssl_dh = </etc/dovecot/dh.pem"
            else:
                ssl_conf = re.sub(r'\nssl_dh = </etc/dovecot/dh.pem', '', ssl_conf)
                os.remove('/etc/dovecot/dh.pem')
        public.writeFile(ssl_file, ssl_conf)

    # 设置ssl
    def set_ssl(self, args):
        path = '{}/cert/'.format(self.__setupPath)
        csrpath = path + "fullchain.pem"
        keypath = path + "privkey.pem"
        backup_cert = '/tmp/backup_cert_mail_sys'
        if hasattr(args, "act") and args.act == "1":
            if args.key.find('KEY') == -1: return public.returnMsg(False, 'Private Key ERROR, please check!')
            if args.csr.find('CERTIFICATE') == -1: return public.returnMsg(False, 'Certificate ERROR, please check!')
            public.writeFile('/tmp/mail_cert.pl', str(args.csr))
            if not public.CheckCert('/tmp/mail_cert.pl'): return public.returnMsg(False,
                                                                                  'Certificate ERROR, please paste the correct certificate in pem format!')
            if os.path.exists(backup_cert): shutil.rmtree(backup_cert)
            if os.path.exists(path): shutil.move(path, backup_cert)
            if os.path.exists(path): shutil.rmtree(path)

            os.makedirs(path)
            public.writeFile(keypath, args.key)
            public.writeFile(csrpath, args.csr)
        else:
            if os.path.exists(csrpath):
                os.remove(csrpath)
            if os.path.exists(keypath):
                os.remove(keypath)

        # 写入配置文件
        p_result = self.set_postfix_ssl(csrpath, keypath, args.act)
        if p_result: return p_result
        d_result = self.set_dovecot_ssl(csrpath, keypath, args.act)
        if d_result: return d_result

        import time
        for i in ["dovecot", "postfix"]:
            args.service = i
            args.type = "restart"
            self.service_admin(args)
            time.sleep(1)
        # 清理备份证书
        if os.path.exists(backup_cert): shutil.rmtree(backup_cert)
        return public.returnMsg(True, 'Successful setup')

    # 获取ssl状态
    def get_ssl_status(self, args):
        path = '{0}/cert/'.format(self.__setupPath)
        csrpath = path + "fullchain.pem"
        keypath = path + "privkey.pem"
        if not (os.path.exists(csrpath) and os.path.exists(keypath)):
            return False
        main_file = self.postfix_main_cf
        main_conf = public.readFile(main_file)
        master_file = "/etc/postfix/master"
        master_conf = public.readFile(master_file)
        dovecot_ssl_file = "/etc/dovecot/conf.d/10-ssl.conf"
        dovecot_ssl_conf = public.readFile(dovecot_ssl_file)
        if main_conf:
            if csrpath not in main_conf and keypath not in main_conf:
                return False
        if master_conf:
            rep = r"\n*\s*-o\s+smtpd_sasl_auth_enable\s*=\s*yes"
            if not re.search(rep, master_conf):
                return False
        if dovecot_ssl_conf:
            if csrpath not in main_conf and keypath not in main_conf:
                return False
        return True

    # 获取可以监听的IP
    def _get_all_ip(self):
        import psutil

        public_ip = self._get_pubilc_ip()
        net_info = psutil.net_if_addrs()
        addr = []
        for i in net_info.values():
            addr.append(i[0].address)
        ip_address = public.readFile('/www/server/panel/data/iplist.txt').strip()
        if ip_address not in addr:
            addr.append(ip_address)
        if public_ip not in addr:
            addr.append(public_ip)
        return addr

    def get_mail_forward(self, args):
        result = self.M('alias').select()
        return result

    # 设置邮件转发
    def set_mail_forward(self, args):
        """
        user            domain_name/email_address
        forward_user    email_address
        domain          domain
        active          0/1
        :param args:
        :return:
        """
        # 检查被转发用户是否存在
        if self.M('alias').where('address=?', args.user).count() > 0:
            return public.returnMsg(False, 'The forward user already exists')
        # 检查域名是否存在
        if self.M('domain').where('domain=?', args.domain).count() <= 0:
            return public.returnMsg(False, 'Domain name does not exist in the mail server')
        # 检查被用户是否存在邮局内
        if self.M('mailbox').where('username=?', args.user).count() <= 0 and args.user[0] != '@':
            return public.returnMsg(False, 'Forwarded user does not exist')
        # 换行符替换为逗号
        tmp = args.forward_user.split('\\n')
        if "\n" in tmp[0]:
            tmp = tmp[0].split('\n')
        forward_user = []
        for i in tmp:
            if not i:
                continue
            forward_user.append(i)
        forward_users = ",".join(forward_user)
        create_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.M('alias').add('address,goto,domain,created,modified,active',
                            (args.user, forward_users, args.domain, create_time, create_time, args.active))
        return public.returnMsg(True, 'Mail forwarding added successfully')

    def edit_mail_forward(self, args):
        if self.M('alias').where('address=?', args.user).count() == 0:
            return public.returnMsg(False, 'The forward user not exists')
        # 换行符替换为逗号
        tmp = args.forward_user.split('\\n')
        if "\n" in tmp[0]:
            tmp = tmp[0].split('\n')
        forward_user = []
        for i in tmp:
            if not i:
                continue
            forward_user.append(i)
        forward_users = ",".join(forward_user)
        modified_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        self.M('alias').where('address=?', args.user).save(
            'goto,modified,active', (forward_users, modified_time, args.active))
        return public.returnMsg(True, 'Mail forwarding modified successfully')

    def delete_mail_forward(self, args):
        if self.M('alias').where('address=?', args.user).count() == 0:
            return public.returnMsg(False, 'The forward user not exists')
        self.M('alias').where('address=?', args.user).delete()
        return public.returnMsg(True, 'Mail forwarding delete successfully')

    def get_bcc(self, args):
        forward = public.readFile(self._forward_conf)
        if forward:
            forward = json.loads(forward)
        else:
            forward = {"recipient": [], "sender": []}
        return forward

    # 设置邮件秘抄
    def set_mail_bcc(self, args):
        """
        type            sender/recipien
        user            domain_name/email_address
        forward_user    email_address
        forward_name    forward name
        domain          domain
        :param args:
        :return:
        """
        if 'domain' not in args:
            args.domain = args.user.strip().split('@')[1]
        data = self.get_bcc(args)
        for d in data[args.type]:
            if args.user == d["user"] and args.forward_user == d["forward_user"]:
                return public.returnMsg(False, "Forward name already exists")
        rep = r"^(?=^.{3,255}$)[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62}(\.[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62})+$"
        if re.search(rep, args.user):
            content = "\n@{} {}".format(args.user, args.forward_user)
        else:
            content = "\n{} {}".format(args.user, args.forward_user)
        # 密抄文件
        bcc_file = "/etc/postfix/{}_bcc".format(args.type)
        public.writeFile(bcc_file, content, "a+")
        data[args.type].append({"domain": args.domain, "user": args.user, "forward_user": args.forward_user})
        public.writeFile(self._forward_conf, json.dumps(data))
        for i in ["/etc/postfix/sender_bcc", "/etc/postfix/recipient_bcc"]:
            if not os.path.exists(i):
                public.writeFile(i, "")
        bcc_conf = '\nrecipient_bcc_maps = hash:/etc/postfix/recipient_bcc\nsender_bcc_maps = hash:/etc/postfix/sender_bcc\n'
        public.writeFile(self.postfix_main_cf, bcc_conf, 'a+')

        shell_str = '''
postmap /etc/postfix/recipient_bcc
postmap /etc/postfix/sender_bcc
systemctl reload postfix
'''
        public.ExecShell(shell_str)
        return public.returnMsg(True, "Set up successfully")

    # 删除邮件秘送
    def del_bcc(self, args):
        data = self.get_bcc(args)
        bcc_file = "/etc/postfix/{}_bcc".format(args.type)
        conf = public.readFile(bcc_file)
        n = 0
        rep = r"\n*{}\s+{}".format(args.user, args.forward_user)
        for d in data[args.type]:
            if args.user == d["user"] and args.forward_user == d["forward_user"]:
                del (data[args.type][n])
                public.writeFile(self._forward_conf, json.dumps(data))
                conf = re.sub(rep, '', conf)
                public.writeFile(bcc_file, conf)
                public.ExecShell('postmap {} && systemctl reload postfix'.format(bcc_file))
                return public.returnMsg(True, 'Successfully deleted')
            n += 1
        return public.returnMsg(True, 'Failed to delete')

    # 设置邮件中继
    def set_smtp_relay(self, args):
        """
            username: mailgun的用户名
            passwd: mailgun的密码
            smtphost: smtp地址
            port: smtp端口
        """
        username = args.username
        passwd = args.passwd
        smtphost = args.smtphost
        port = args.port
        add_paramater = """
#BEGIN_POSTFIX_RELAY
relayhost = [{smtphost}]:{port}
smtp_sasl_auth_enable = yes
smtp_sasl_password_maps = static:{username}:{passwd}
smtp_sasl_security_options = noanonymous
#END_POSTFIX_RELAY
""".format(smtphost=smtphost, port=port, username=username, passwd=passwd)
        if self.get_smtp_status(args)['status']:
            return public.returnMsg(False, "The smtp relay already exists")
        public.writeFile(self.postfix_main_cf, add_paramater, 'a+')
        return public.returnMsg(True, "Setup successfully")

    # 获取中继信息
    def get_smtp_status(self, args):
        conf = public.readFile(self.postfix_main_cf)
        if not conf:
            return public.returnMsg(False, "No configuration information found")
        if "BEGIN_POSTFIX_RELAY" in conf:
            host_port_reg = r"relayhost\s*=\s*\[([\.\w]+)\]:(\d+)"
            tmp = re.search(host_port_reg, conf)
            host = port = user = passwd = ""
            if tmp:
                host = tmp.groups(1)[0]
                port = tmp.groups(2)[1]
            user_passwd_reg = r"smtp_sasl_password_maps\s*=\s*static:(.*?):(.*)"
            tmp = re.search(user_passwd_reg, conf)
            if tmp:
                user = tmp.groups(1)[0]
                passwd = tmp.groups(2)[1]
            return public.returnMsg(True, {"host": host, "port": port, "user": user, "passwd": passwd})
        return public.returnMsg(False, "No configuration information found")

    # 取消中继
    def cancel_smtp_relay(self, args):
        conf = public.readFile(self.postfix_main_cf)
        reg = r"\n#BEGIN_POSTFIX_RELAY(.|\n)+#END_POSTFIX_RELAY\n"
        tmp = re.search(reg, conf)
        if not tmp:
            return public.returnMsg(False, "The smtp relay does not exist")
        conf = re.sub(reg, "", conf)
        public.writeFile(self.postfix_main_cf, conf)
        return public.returnMsg(True, "Setup successfully")

    # 获取反垃圾服务监听ip和端口
    def _get_anti_server_ip_port(self, get):
        conf = public.readFile('/etc/amavisd/amavisd.conf')
        if not os.path.exists('/etc/redhat-release'):
            conf = public.readFile('/etc/amavis/conf.d/20-debian_defaults')
        reg = '\n\${}\s*=\s*[\'\"]?(.*?)[\'\"]?;'
        spam_server_ip_reg = reg.format('inet_socket_bind')
        spam_server_port_reg = reg.format('inet_socket_port')
        spam_server_ip = re.search(spam_server_ip_reg, conf)
        if spam_server_ip:
            spam_server_ip = spam_server_ip.groups(1)[0]
        else:
            spam_server_ip = '127.0.0.1'
        spam_server_port = re.search(spam_server_port_reg, conf)
        if spam_server_port:
            spam_server_port = spam_server_port.groups(1)[0]
        else:
            spam_server_port = '10024'
        return {'spam_server_port': spam_server_port, 'spam_server_ip': spam_server_ip}

    # 设置postfix main配置支持反垃圾
    def _set_main_cf_anti_spam(self, args):
        conf = public.readFile(self.postfix_main_cf)
        anti_spam_conf = """
##BT-ANTISPAM-BEGIN
content_filter=amavisfeed:[{}]:{}
##BT-ANTISPAM-END
"""
        if 'amavisfeed' in conf:
            return
        if args.spam_server_ip == 'localhost':
            spam_server_info = self._get_anti_server_ip_port(get=None)
            anti_spam_conf = anti_spam_conf.format(spam_server_info['spam_server_ip'],
                                                   spam_server_info['spam_server_port'])
            public.writeFile(self.postfix_main_cf, conf + anti_spam_conf)
        else:
            anti_spam_conf = anti_spam_conf.format(args.spam_server_ip, args.spam_server_port)
            public.writeFile(self.postfix_main_cf, conf + anti_spam_conf)

    # 设置postfix master配置支持反垃圾
    def _set_master_cf_anti_spam(self):
        master_file = '/etc/postfix/master.cf'
        conf = public.readFile(master_file)
        if re.search('##BT-ANTISPAM-BEGIN', conf):
            return
        anti_conf = """
##BT-ANTISPAM-BEGIN
amavisfeed unix -   -   n   -   2    smtp
 -o smtp_data_done_timeout=1000
 -o smtp_send_xforward_command=yes
 -o disable_dns_lookups=yes
 -o max_use=20
127.0.0.1:10025 inet n -   n   -   -    smtpd
 -o content_filter=
 -o smtpd_delay_reject=no
 -o smtpd_client_restrictions=permit_mynetworks,reject
 -o smtpd_helo_restrictions=
 -o smtpd_sender_restrictions=
 -o smtpd_recipient_restrictions=permit_mynetworks,reject
 -o smtpd_data_restrictions=reject_unauth_pipelining
 -o smtpd_end_of_data_restrictions=
 -o smtpd_restriction_classes=
 -o mynetworks=127.0.0.0/8,192.168.0.0/16
 -o smtpd_error_sleep_time=0
 -o smtpd_soft_error_limit=1001
 -o smtpd_hard_error_limit=1000
 -o smtpd_client_connection_count_limit=0
 -o smtpd_client_connection_rate_limit=0
 -o receive_override_options=no_header_body_checks,no_unknown_recipient_checks,no_milters
 -o local_header_rewrite_clients=
##BT-ANTISPAM-END
 """
        public.writeFile(master_file, conf + anti_conf)

    def _set_dovecot_cf_anti_spam(self):
        '''
        设置dovecot配置支持反垃圾
        :return:
        '''
        # 判断dovecot-sieve是否安装成功
        if os.path.exists('/etc/dovecot/conf.d/90-sieve.conf'):
            download_conf_shell = '''
wget "{download_conf_url}/mail_sys/dovecot/dovecot.conf" -O /etc/dovecot/dovecot.conf -T 10
wget "{download_conf_url}/mail_sys/dovecot/15-lda.conf" -O /etc/dovecot/conf.d/15-lda.conf -T 10
wget "{download_conf_url}/mail_sys/dovecot/20-lmtp.conf" -O /etc/dovecot/conf.d/20-lmtp.conf -T 10
wget "{download_conf_url}/mail_sys/dovecot/90-plugin.conf" -O /etc/dovecot/conf.d/90-plugin.conf -T 10
wget "{download_conf_url}/mail_sys/dovecot/90-sieve.conf" -O /etc/dovecot/conf.d/90-sieve.conf -T 10
    '''.format(download_conf_url=public.get_url())
            public.ExecShell(download_conf_shell)
            if not os.path.exists('/etc/dovecot/sieve'):
                os.makedirs('/etc/dovecot/sieve')
            default_sieve = '''require "fileinto";
if header :contains "X-Spam-Flag" "YES" {
    fileinto "Junk";
}'''
            public.writeFile('/etc/dovecot/sieve/default.sieve', default_sieve)
            public.ExecShell('chown -R vmail:dovecot /etc/dovecot')

    # 开启反垃圾
    def turn_on_anti_spam(self, args):
        if args.spam_server_ip != 'localhost':
            return public.returnMsg(False, 'Currently does not support remote scanning, the function is being tested')
        if args.spam_server_ip == 'localhost' and not os.path.exists('/www/server/panel/plugin/anti_spam'):
            return public.returnMsg(False, 'Please go to the app store to install the anti-spam')
        self._set_main_cf_anti_spam(args)
        self._set_master_cf_anti_spam()
        self._set_dovecot_cf_anti_spam()
        public.ExecShell('/usr/sbin/postfix reload')
        public.ExecShell('systemctl restart dovecot')
        public.ExecShell('systemctl restart spamassassin')
        return public.returnMsg(True, 'Setup successfully')

    # # 关闭反垃圾
    def turn_off_anti_spam(self, args):
        # 清理master配置
        master_file = '/etc/postfix/master.cf'
        conf = public.readFile(master_file)
        reg = "\n##BT-ANTISPAM-BEGIN(.|\n)+##BT-ANTISPAM-END\n"
        conf = re.sub(reg, '', conf)
        public.writeFile(master_file, conf)
        # 清理main配置
        conf = public.readFile(self.postfix_main_cf)
        conf = re.sub(reg, '', conf)
        public.writeFile(self.postfix_main_cf, conf)
        public.ExecShell('/usr/sbin/postfix reload')
        return public.returnMsg(True, 'Closed successfully')

    # 获取反垃圾开启状态
    def get_anti_spam_status(self, args):
        conf = public.readFile(self.postfix_main_cf)
        if re.search('##BT-ANTISPAM-BEGIN', conf):
            return True
        return False

    # 获取数据备份任务是否存在的状态
    def get_backup_task_status(self, get):
        c_id = public.M('crontab').where('name=?', u'[Do not delete] Mail server data backup task').getField('id')
        if not c_id: return public.returnMsg(False, 'Backup task does not exist!')
        data = public.M('crontab').where('name=?', u'[Do not delete] Mail server data backup task').find()
        return public.returnMsg(True, data)

    # 打开数据备份任务
    def open_backup_task(self, get):
        import crontab
        p = crontab.crontab()

        c_id = public.M('crontab').where('name=?', u'[Do not delete] Mail server data backup task').getField('id')
        if c_id:
            data = {}
            data['id'] = c_id
            data['name'] = u'[Do not delete] Mail server data backup task'
            data['type'] = get.type
            data['where1'] = get.where1 if 'where1' in get else ''
            data['sBody'] = ''
            data['backupTo'] = get.backupTo if 'backupTo' in get else 'localhost'
            data['sType'] = 'path'
            data['hour'] = get.hour if 'hour' in get else ''
            data['minute'] = get.minute if 'minute' in get else ''
            data['week'] = get.week if 'week' in get else ''
            data['sName'] = '/www/vmail/'
            data['urladdress'] = ''
            data['save'] = get.save
            p.modify_crond(data)
            return public.returnMsg(True, 'Edit successful!')
        else:
            data = {}
            data['name'] = u'[Do not delete] Mail server data backup task'
            data['type'] = get.type
            data['where1'] = get.where1 if 'where1' in get else ''
            data['sBody'] = ''
            data['backupTo'] = get.backupTo if 'backupTo' in get else 'localhost'
            data['sType'] = 'path'
            data['hour'] = get.hour if 'hour' in get else ''
            data['minute'] = get.minute if 'minute' in get else ''
            data['week'] = get.week if 'week' in get else ''
            data['sName'] = '/www/vmail/'
            data['urladdress'] = ''
            data['save'] = get.save
            p.AddCrontab(data)
            return public.returnMsg(True, 'Setup successful!')

    # 关闭数据备份任务
    def close_backup_task(self, get):
        import crontab

        p = crontab.crontab()
        c_id = public.M('crontab').where('name=?', u'[Do not delete] Mail server data backup task').getField('id')
        if not c_id: return public.returnMsg(False, 'Backup task does not exist!')
        args = {"id": c_id}
        p.DelCrontab(args)
        return public.returnMsg(True, 'Close successful!')

    # 获取已安装云存储插件列表
    def get_cloud_storage_list(self, get):
        data = []
        tmp = public.readFile('data/libList.conf')
        libs = json.loads(tmp)
        for lib in libs:
            if 'opt' not in lib: continue
            filename = 'plugin/{}'.format(lib['opt'])
            if not os.path.exists(filename): continue
            data.append({'name': lib['name'], 'value': lib['opt']})
        return data

    # 获取本地备份文件列表
    def get_backup_file_list(self, get):
        dir_path = get.path.strip()
        if not os.path.exists(dir_path):
            os.makedirs(dir_path, 384)
        files = []
        for file_name in os.listdir(dir_path):
            if not file_name.startswith('path_vmail'): continue
            file_path = os.path.join(dir_path, file_name)
            if not os.path.exists(file_path): continue
            f_info = {}
            f_info['name'] = file_name
            f_info['mtime'] = os.path.getmtime(file_path)
            files.append(f_info)
        files = sorted(files, key=lambda x: x['mtime'], reverse=True)
        return files

    def get_backup_path(selfg,get):
        path = public.M('config').where("id=?", (1, )).getField('backup_path')
        path = os.path.join(path, 'path')
        return path

    # 数据恢复
    def restore(self, get):
        file_path = get.file_path.strip()
        if not os.path.exists(file_path):
            return public.returnMsg(False, 'File does not exist!')
        cmd = 'cd {} && tar -xzvf {} 2>&1'.format('/www', file_path)
        print(cmd)
        public.ExecShell(cmd)
        return public.returnMsg(True, 'Recovery complete')

    # 设置收件箱和发件箱邮件保存的天数
    def set_save_day(self, get):
        public.writeFile(self._save_conf, get.save_day)
        return public.returnMsg(True, 'Setup successful')

    # 获取收件箱和发件箱邮件保存的天数
    def get_save_day(self, get):
        if not os.path.exists(self._save_conf):
            return 0
        return int(public.readFile(self._save_conf))

    def _get_old_certificate_path(self, conf):
        # 以前设置的获取证书路径
        cert_file_reg = r'#smtpd_tls_cert_file\s*=\s*(.*)'
        cert_key_reg = r'#smtpd_tls_key_file\s*=\s*(.*)'
        cert_tmp = re.search(cert_file_reg, conf)
        if cert_tmp:
            cert_file = cert_tmp.groups(1)[0]
            cert_key = re.search(cert_key_reg, conf).groups(1)[0]
        else:
            cert_key = '/etc/pki/dovecot/private/dovecot.pem'
            cert_file = '/etc/pki/dovecot/certs/dovecot.pem'
        return {'cert_key': cert_key, 'cert_file': cert_file}

    def _set_new_certificate_conf(self, conf, cert_file, cert_key):
        # 添加新的证书配置
        if not cert_key:
            cert_key = '/etc/pki/dovecot/private/dovecot.pem'
            cert_file = '/etc/pki/dovecot/certs/dovecot.pem'
        smtpd_tls_chain_files = '\nsmtpd_tls_chain_files = {},{}'.format(cert_key, cert_file)
        reg = r'\nsmtpd_tls_chain_files\s*=(.*)'
        tmp = re.search(reg, conf)
        if tmp:
            conf = re.sub(reg, smtpd_tls_chain_files, conf)
            return conf
        tls_server_sni_maps = '\ntls_server_sni_maps = hash:/etc/postfix/vmail_ssl.map\n'
        conf = conf + smtpd_tls_chain_files + tls_server_sni_maps
        return conf

    def _set_vmail_certificate(self, args, arecord, cert_file, cert_key):
        # 设置证书给某个A记录
        conf = public.readFile('/etc/postfix/vmail_ssl.map')
        if not conf:
            conf = ''
        if args.act == 'delete' and arecord in conf:
            reg = '{}.*\n'.format(arecord)
            conf = re.sub(reg, '', conf)
            reg = '{}.*\n'.format(args.domain)
            conf = re.sub(reg, '', conf)
        else:
            if arecord in conf:
                return True
            conf += '{} {} {}\n'.format(args.domain, cert_key, cert_file)
            conf += '{} {} {}\n'.format(arecord, cert_key, cert_file)
        public.writeFile('/etc/postfix/vmail_ssl.map', conf)

    def _set_dovecot_cert_global(self,cert_file,cert_key,conf):
        default_cert_key = 'ssl_key\s*=\s*<\s*/etc/pki/dovecot/private/dovecot.pem'
        default_cert_file = 'ssl_cert\s*=\s*<\s*/etc/pki/dovecot/certs/dovecot.pem'
        if not re.search(default_cert_file,conf):
            return conf
        conf = re.sub(default_cert_file, "ssl_cert = <{}".format(cert_file),conf)
        conf = re.sub(default_cert_key, "ssl_key = <{}".format(cert_key), conf)
        return conf

    # 修改dovecot的ssl配置
    def _set_dovecot_certificate(self, args, a_record,cert_file,cert_key):
        dovecot_version = self.get_dovecot_version()
        ssl_file = "/etc/dovecot/conf.d/10-ssl.conf"
        ssl_conf = public.readFile(ssl_file)
        if not ssl_conf:
            return public.returnMsg(False, "Can not find the dovecot configuration file {}".format(ssl_file))
        # 2.3版本的dovecot要加上ssl_dh配置
        if dovecot_version.startswith('2.3'):
            if args.act == 'add':
                if not os.path.exists('/etc/dovecot/dh.pem') or os.path.getsize('/etc/dovecot/dh.pem') < 300:
                    public.ExecShell('openssl dhparam 2048 > /etc/dovecot/dh.pem')
                if 'ssl_dh = </etc/dovecot/dh.pem' not in ssl_conf:
                    ssl_conf  = ssl_conf + "\nssl_dh = </etc/dovecot/dh.pem"
        # 将自签证书替换为用户设置的证书
        reg_cert = 'local_name\s+{}'.format(a_record)
        if args.act == 'add' and not re.search(reg_cert, ssl_conf):
            ssl_conf = self._set_dovecot_cert_global(cert_file,cert_key,ssl_conf)
            domain_ssl_conf = """
#DOMAIN_SSL_BEGIN_%s
local_name %s {
    ssl_cert = < %s
    ssl_key = < %s
}
#DOMAIN_SSL_END_%s""" % (a_record, a_record, cert_file, cert_key, a_record)
            reg = 'ssl\s*=\s*yes'
            ssl_conf = re.sub(reg, 'ssl = yes' + domain_ssl_conf, ssl_conf)
        if args.act == 'delete':
            reg = '#DOMAIN_SSL_BEGIN_{a}(.|\n)+#DOMAIN_SSL_END_{a}\n'.format(a=a_record)
            ssl_conf = re.sub(reg, '', ssl_conf)

        public.writeFile(ssl_file, ssl_conf)
        public.ExecShell('systemctl restart dovecot')

    def _verify_certificate(self, args,path,csrpath,keypath):
        # 验证并写入证书
        # path = '{}/cert/{}/'.format(self.__setupPath, args.domain)
        # csrpath = path + "fullchain.pem"
        # keypath = path + "privkey.pem"
        backup_cert = '/tmp/backup_cert_mail_sys'
        if hasattr(args, "act") and args.act == "add":
            if args.key.find('KEY') == -1: return public.returnMsg(False, 'Private Key ERROR, please check!')
            if args.csr.find('CERTIFICATE') == -1: return public.returnMsg(False, 'Certificate ERROR, please check!')
            public.writeFile('/tmp/mail_cert.pl', str(args.csr))
            if not public.CheckCert('/tmp/mail_cert.pl'): return public.returnMsg(False,
                                                                                  'Certificate ERROR, please paste the correct certificate in pem format!')
            if os.path.exists(backup_cert): shutil.rmtree(backup_cert)
            if os.path.exists(path): shutil.move(path, backup_cert)
            if os.path.exists(path): shutil.rmtree(path)
            os.makedirs(path)
            public.writeFile(keypath, args.key)
            os.chown(keypath, 0, 0)
            os.chmod(keypath, 0o600)
            public.writeFile(csrpath, args.csr)
            os.chown(csrpath, 0, 0)
            os.chmod(csrpath, 0o600)
        # else:
        #     if os.path.exists(csrpath):
        #         public.ExecShell('rm -rf {}'.format(path))

    def _check_postfix_conf(self):
        result = public.process_exists('master', '/usr/libexec/postfix/master')
        if 'ubuntu 2' in self._get_ubuntu_version() or 'debian gnu/linux 10' in self._get_ubuntu_version():
            result = public.process_exists('master', '/usr/lib/postfix/sbin/master')
        return result

    def _get_ubuntu_version(self):
        return public.readFile('/etc/issue').strip().split("\n")[0].replace('\\n', '').replace('\l', '').strip().lower()

    def _modify_old_ssl_perameter(self, conf):
        if not os.path.exists('/etc/postfix/vmail_ssl.map'):
            # 注释以前的证书设置
            if '#smtpd_tls_cert_file' not in conf:
                conf = conf.replace('smtpd_tls_cert_file', '#smtpd_tls_cert_file')
                conf = conf.replace('smtpd_tls_key_file', '#smtpd_tls_key_file')
            # 以前设置的获取证书路径
            old_cert_info = self._get_old_certificate_path(conf)
            # 设置新的证书配置和默认TLS配置
            if 'tls_server_sni_maps' not in conf:
                conf = self._set_new_certificate_conf(conf, old_cert_info['cert_file'], old_cert_info['cert_key'])
        public.writeFile(self.postfix_main_cf, conf)

    def _fix_default_cert(self, conf, cert_file, cert_key):
        reg = r'smtpd_tls_chain_files\s*=(.*)'
        tmp = re.search(reg, conf)
        if not tmp:
            return conf
        tmp = tmp.groups()[0]
        if len(tmp) < 5 or 'dovecot.pem' in conf:
            conf = self._set_new_certificate_conf(conf, cert_file, cert_key)
        return conf

    def _set_master_ssl(self):
        master_file = "/etc/postfix/master.cf"
        master_conf = public.readFile(master_file)
        master_rep = r"\n*#\s*-o\s+smtpd_tls_auth_only=yes"
        master_str = "\n  -o smtpd_tls_auth_only=yes"
        master_rep1 = r"\n*#\s*-o\s+smtpd_tls_wrappermode=yes"
        master_str1 = "\n  -o smtpd_tls_wrappermode=yes"
        master_conf = re.sub(master_rep, master_str, master_conf)
        master_conf = re.sub(master_rep1, master_str1, master_conf)
        public.writeFile(master_file, master_conf)

    def set_mail_certificate_multiple(self, args):
        '''
        :param args: domain 要设置证书的域名
        :param args: csr
        :param args: key
        :param args: act add/delete
        :return:
        '''
        if not os.path.exists('/etc/redhat-release') and 'debian gnu/linux 10' not in self._get_ubuntu_version():
            if 'ubuntu 2' not in self._get_ubuntu_version():
                if args.act == 'add':
                    args.act = "1"
                else:
                    args.act = "0"
                pstr = """
{postconf} -e "smtpd_tls_cert_file = /etc/pki/dovecot/certs/dovecot.pem"
{postconf} -e "smtpd_tls_key_file = /etc/pki/dovecot/private/dovecot.pem"
    """.format(postconf=self.get_postconf())
                public.ExecShell(pstr)
                return self.set_ssl(args)
        conf = public.readFile(self.postfix_main_cf)
        domain = args.domain
        cert_path = '/www/server/panel/plugin/mail_sys/cert/{}'.format(domain)
        cert_file = "{}/fullchain.pem".format(cert_path)
        cert_key = "{}/privkey.pem".format(cert_path)
        if not os.path.exists(cert_path):
            os.makedirs(cert_path)
        # 备份配置文件
        public.back_file(self.postfix_main_cf)
        # 在main注释smtpd_tls_cert_file，smtpd_tls_key_file参数
        # 添加smtpd_tls_chain_files和tls_server_sni_maps，3.4+支持
        conf = self._fix_default_cert(conf,cert_file,cert_key)
        self._modify_old_ssl_perameter(conf)
        # 修改master.cf开启tls/ssl
        self._set_master_ssl()
        # 获取域名的A记录
        arecord = self.M('domain').where('domain=?', domain).field('a_record').find()['a_record']
        if arecord == '':
            return public.returnMsg(False, 'The set domain name does not exist')
        # 验证域名证书是否有效
        if args.csr != '':
            verify_result = self._verify_certificate(args,cert_path,cert_file,cert_key)
            if verify_result:
                return verify_result
        # 将证书配置到vmail_ssl.map
        self._set_vmail_certificate(args, arecord, cert_file, cert_key)
        self._set_dovecot_certificate(args, arecord, cert_file, cert_key)
        # if args.act == 'delete':
        #     pem = "{}/cert/{}/fullchain.pem".format(self.__setupPath,domain)
        #     key = "{}/cert/{}/privkey.pem".format(self.__setupPath,domain)
        #     if os.path.exists(pem):
        #         os.remove(pem)
        #     if os.path.exists(key):
        #         os.remove(key)
        public.ExecShell('postmap -F hash:/etc/postfix/vmail_ssl.map && systemctl restart postfix')
        if not self._check_postfix_conf():
            public.restore_file(self.postfix_main_cf)
            return public.returnMsg(False, 'Setup Failed, restore the configuration file now')
        return public.returnMsg(True, 'Setup Successful')

    def get_multiple_certificate(self, args):
        """
            @name 获取某个域名的证书内容
            @author zhwen<zhw@bt.cn>
            @param domain 需要获取的域名
        """
        domain = args.domain
        path = '{}/cert/{}/'.format(self.__setupPath, domain)
        if not os.path.exists('/etc/redhat-release') and 'debian gnu/linux 10' not in self._get_ubuntu_version():
            if 'ubuntu 2' not in self._get_ubuntu_version():
                path = '/www/server/panel/plugin/mail_sys/cert/'
        csrpath = path + "fullchain.pem"
        keypath = path + "privkey.pem"
        if not os.path.exists(csrpath):
            return public.returnMsg(False, 'SSL has not been set up for this domain')
        csr = public.readFile(csrpath)
        key = public.readFile(keypath)
        return {'csr': csr, 'key': key}

    def _get_multiple_certificate_domain_status(self, domain):
        path = '/www/server/panel/plugin/mail_sys/cert/{}/fullchain.pem'.format(domain)
        ssl_conf = public.readFile('/etc/postfix/vmail_ssl.map')
        if not os.path.exists('/etc/redhat-release') and 'debian gnu/linux 10' not in self._get_ubuntu_version():
            if 'ubuntu 2' not in self._get_ubuntu_version():
                path = '/www/server/panel/plugin/mail_sys/cert/fullchain.pem'
        if not os.path.exists(path):
            return False
        if not ssl_conf or domain not in ssl_conf:
            return False
        return True

    # 备份配置文件
    def back_file(self, file, act=None):
        """
            @name 备份配置文件
            @author zhwen<zhw@bt.cn>
            @param file 需要备份的文件
            @param act 如果存在，则备份一份作为默认配置
        """
        file_type = "_bak"
        if act:
            file_type = "_def"
        public.ExecShell("/usr/bin/cp -p {0} {1}".format(
            file, file + file_type))

    # 还原配置文件
    def restore_file(self, file, act=None):
        """
            @name 还原配置文件
            @author zhwen<zhw@bt.cn>
            @param file 需要还原的文件
            @param act 如果存在，则还原默认配置
        """
        file_type = "_bak"
        if act:
            file_type = "_def"
        public.ExecShell("/usr/bin/cp -p {1} {0}".format(
            file, file + file_type))

    def enable_catchall(self, args):
        """
            @name 设置邮局捕获不存在的用户邮局并转发到指定邮箱
            @author zhwen<zhw@bt.cn>
            @param domain 需要捕获的域名
            @param email 不存在的用户将会转发到这个用户
        """
        conf = public.readFile(self.postfix_main_cf)
        catchall_exist = self._get_catchall_status(args.domain)
        domain = '@' + args.domain.strip()
        email = args.email.strip()
        if catchall_exist:
            new_conf = 'virtual_alias_maps = sqlite:/etc/postfix/sqlite_virtual_alias_maps.cf, sqlite:/etc/postfix/sqlite_virtual_alias_domain_maps.cf, sqlite:/etc/postfix/sqlite_virtual_alias_domain_catchall_maps.cf'
            self.M('alias').where('address=?', domain).delete()
        else:
            create_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            self.M('alias').add('address,goto,domain,created,modified,active',
                                (domain, email, args.domain.strip(), create_time, create_time, '1'))
            new_conf = 'virtual_alias_maps= sqlite:/etc/postfix/btrule.cf'
            if public.FileMd5('/etc/postfix/btrule.cf') != 'c96897b9285db8b53f2e1e2358918264':
                public.ExecShell(
                    'wget -O /etc/postfix/btrule.cf {}/mail_sys/postfix/btrule.cf -T 10'.format(public.get_url()))
        conf = re.sub(r'virtual_alias_maps\s*=.*', new_conf, conf)
        public.writeFile(self.postfix_main_cf, conf)
        public.ExecShell('systemctl restart postfix')
        return public.returnMsg(True, 'Setup Successfully')

    def _get_catchall_status(self, domain):
        """
            @name 获取某个域名下catchall是否开启
            @author zhwen<zhw@bt.cn>
            @param domain 需要捕获的域名
        """
        domain = '@' + domain.strip()
        conf = public.readFile(self.postfix_main_cf)
        reg = r'virtual_alias_maps\s*=\s*sqlite:/etc/postfix/btrule.cf'
        if not conf:
            return False
        catchall_exist = re.search(reg, conf)
        if not catchall_exist:
            return False
        result = self.M('alias').where('address=?', domain).select()
        if result:
            return True
        return False

    def get_junk_mails(self, args):
        '''
        获取垃圾邮件列表
        :param args:
        :return:
        '''
        import email
        import receive_mail
        reload(receive_mail)

        if 'username' not in args:
            return public.returnMsg(False, 'Please input account name')
        username = args.username
        if '@' not in username:
            return public.returnMsg(False, 'Invalid account name, for example: xx@example.com')
        local_part, domain = username.split('@')
        if 'p' not in args:
            args.p = 1
        if 'p=' in args.p:
            args.p = args.p.split('p=')[-1]

        receive_mail_client = receive_mail.ReceiveMail()
        mail_list = []
        try:
            dir_path = '/www/vmail/{0}/{1}/.Junk/cur'.format(domain, local_part)
            if os.path.isdir(dir_path):
                # 先将new文件夹的邮件移动到cur文件夹
                new_path = '/www/vmail/{0}/{1}/.Junk/new'.format(domain, local_part)
                if os.path.isdir(new_path):
                    for file in os.listdir(new_path):
                        src = os.path.join(new_path, file)
                        dst = os.path.join(dir_path, file)
                        shutil.move(src, dst)
                files = []
                for fname in os.listdir(dir_path):
                    mail_file = os.path.join(dir_path, fname)
                    if not os.path.exists(mail_file): continue
                    f_info = {}
                    f_info['name'] = fname
                    f_info['mtime'] = os.path.getmtime(mail_file)
                    save_day = self.get_save_day(None)
                    if save_day > 0:
                        deltime = int(time.time()) - save_day * 86400
                        if int(f_info['mtime']) < deltime:
                            os.remove(mail_file)
                            continue
                    files.append(f_info)
                files = sorted(files, key=lambda x: x['mtime'], reverse=True)
                page_data = public.get_page(len(files), int(args.p), 10)
                shift = int(page_data['shift'])
                row = int(page_data['row'])
                files = files[shift:shift + row]
                for d in files:
                    mail_file = os.path.join(dir_path, d['name'])
                    encoding = self.get_encoding(mail_file)
                    # if sys.version_info[0] == 2:
                    #     import io
                    #     fp = io.open(mail_file, 'r', encoding=encoding,errors='replace')
                    # else:
                    #     fp = open(mail_file, 'r', encoding=encoding,errors='replace')
                    with open(mail_file, 'rb') as fp:
                        try:
                            # public.writeFile('/tmp/2',str(encoding)+'\n','a+')
                            message = email.message_from_binary_file(fp)
                            mailInfo = receive_mail_client.getMailInfo(msg=message)
                            mailInfo['path'] = mail_file
                            mail_list.append(mailInfo)
                        except:
                            # if sys.version_info[0] == 2:
                            #     import io
                            #     fp = io.open(mail_file, 'rb')
                            # else:
                            #     fp = open(mail_file, 'rb')
                            # try:
                            #     # public.writeFile('/tmp/2',str(encoding)+'\n','a+')
                            #     # message = email.message_from_file(fp)
                            #     try:
                            #         message = email.message_from_binary_file(fp)  # Python 3
                            #     except AttributeError:
                            #         message = email.message_from_file(fp)  # Python 2
                            #     mailInfo = receive_mail_client.getMailInfo(msg=message)
                            #     mailInfo['path'] = mail_file
                            #     mail_list.append(mailInfo)
                            # except:

                            # public.writeFile('/tmp/2', str(
                                # public.get_error_info()) + '\n' + '1111111111111111111111111' + mail_file, 'a+')
                            print(public.get_error_info())
                            continue
                return {'status': True, 'data': mail_list,
                        'page': page_data['page'].replace('/plugin?action=a&name=mail_sys&s=get_junk_mails&p=', '')}
            else:
                page_data = public.get_page(0, int(args.p), 10)
                return {'status': True, 'data': mail_list,
                        'page': page_data['page'].replace('/plugin?action=a&name=mail_sys&s=get_junk_mails&p=', '')}
        except Exception as e:
            print(public.get_error_info())
            return public.returnMsg(False, 'Obtaining failure, reason: [{0}]'.format(str(e)))

    def move_to_junk(self, get):
        '''
        将收件箱的邮件标记为垃圾邮件
        :param get:
        :return:
        '''
        if 'username' not in get:
            return public.returnMsg(False, 'Please input account name')
        username = get.username
        if '@' not in username:
            return public.returnMsg(False, 'Invalid account name, for example: xx@example.com')
        local_part, domain = username.split('@')

        src = get.path.strip()
        if not os.path.exists('/www/vmail/{0}/{1}/.Junk'.format(domain, local_part)):
            data = self.M('mailbox').where('username=?', username).field('password_encode,full_name').find()
            password = self._decode(data['password_encode'])
            self.create_mail_box(username, password)
        if not os.path.exists(src):
            return public.returnMsg(False, 'Mail path does not exist')
        dir_path = '/www/vmail/{0}/{1}/.Junk/cur'.format(domain, local_part)
        dst = os.path.join(dir_path, os.path.basename(src))
        shutil.move(src, dst)
        return public.returnMsg(True, 'Mark successful')

    def move_out_junk(self, get):
        '''
        将垃圾箱的邮件移动到收件箱
        :param get:
        :return:
        '''
        if 'username' not in get:
            return public.returnMsg(False, 'Please input account name')
        username = get.username
        if '@' not in username:
            return public.returnMsg(False, 'Invalid account name, for example: xx@example.com')
        local_part, domain = username.split('@')

        src = get.path.strip()
        if not os.path.exists(src):
            return public.returnMsg(False, 'Mail path does not exist')
        dir_path = '/www/vmail/{0}/{1}/cur'.format(domain, local_part)
        dst = os.path.join(dir_path, os.path.basename(src))
        shutil.move(src, dst)
        return public.returnMsg(True, 'Moved successfully')

    # 获取SSL证书时间到期时间
    def get_ssl_info(self, domain):
        try:
            import data
            fullchain_file = '/www/server/panel/plugin/mail_sys/cert/{}/fullchain.pem'.format(domain)
            os.chown(fullchain_file, 0, 0)
            os.chmod(fullchain_file, 0o600)
            privkey_file = '/www/server/panel/plugin/mail_sys/cert/{}/privkey.pem'.format(domain)
            os.chown(privkey_file, 0, 0)
            os.chmod(privkey_file, 0o600)
            ssl_info = data.data().get_cert_end(fullchain_file)
            if not ssl_info:
                return {'dns':[domain]}
            ssl_info['src'] = public.readFile(fullchain_file)
            ssl_info['key'] = public.readFile(privkey_file)
            ssl_info['endtime'] = int(
                int(time.mktime(time.strptime(ssl_info['notAfter'], "%Y-%m-%d")) - time.time()) / 86400)
            return ssl_info
        except:
            return {'dns':[domain]}

    # 仅支持dns申请
    # 申请证书
    def apply_cert(self, args):
        """
        domains 邮箱域名 ['example.com']
        auth_to CloudFlareDns|email|token 当auth_to 为 dns时是需要手动添加解析
        auto_wildcard = 1
        auth_type = dns
        :param args:
        :return:
        """
        import acme_v2
        domains = json.loads(args.domains)
        apply_cert_module = acme_v2.acme_v2()
        apply_cert = apply_cert_module.apply_cert(domains, 'dns', args.auth_to, auto_wildcard=1)
        return apply_cert

    # 手动验证dns
    def apply_cert_manual(self, args):
        """
        index
        :param args:
        :return:
        """
        import acme_v2
        apply_cert_module = acme_v2.acme_v2()
        return apply_cert_module.apply_cert([], 'dns', 'dns', index=args.index)

    def check_rspamd_route(self,args):
        panel_init = public.readFile("/www/server/panel/BTPanel/__init__.py")
        if "proxy_rspamd_requests" in panel_init:
            return public.returnMsg(True,"")
        return public.returnMsg(False,"")

    @staticmethod
    def change_hostname(args):
        hostname = args.hostname
        rep_domain = "^(?=^.{3,255}$)[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62}(\.[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62})+$"
        if not re.search(rep_domain,hostname):
            return public.returnMsg(False,"Please enter the FQDN (Fully Qualified Domain Name e.g mail.aapanel.com),")
        public.ExecShell('hostnamectl set-hostname --static {}'.format(hostname))
        h = socket.gethostname()
        if h == hostname:
            return public.returnMsg(True,"Setup successfully")
        return public.returnMsg(False, "Setup failed")

    def check_init_result(self,args):
        """
        检查安装结果：
        服务状态
        配置文件完整性
        :return:
        """
        result = dict()
        result['missing_file'] = self.check_confile_completeness()
        result['service_status'] = self.get_service_status()
        return result

    def check_confile_completeness(self):
        file_list = public.readFile("{}/services_file.txt".format(self.__setupPath))
        if not file_list:
            return ["%s/services_file.txt|{download_conf_url}/mail_sys" % self.__setupPath]
        file_list = [i for i in file_list.split()]
        missing_files = []
        for file in file_list:
            tmp = public.readFile(file.split('|')[0])
            if not tmp:
                missing_files.append(file)
        return missing_files

    @staticmethod
    def get_init_log(args=None):
        """
        获取初始化日志
        :param args:
        :return:
        """
        logfile = '/tmp/mail_init.log'
        return public.returnMsg(True, public.GetNumLines(logfile, 50))

    @staticmethod
    def check_smtp_port(args):
        """
        检查服务器能否连接其他服务的25端口
        :param args:
        :return:
        """
        domain = args.domain
        rep_domain = "^(?=^.{3,255}$)[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62}(\.[a-zA-Z0-9\_\-][a-zA-Z0-9\_\-]{0,62})+$"
        if not re.search(rep_domain,domain):
            return public.returnMsg(False,"Please enter the FQDN (Fully Qualified Domain Name e.g smtp.gmail.com),")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((domain, 25))
        if result == 0:
            return public.returnMsg(True,"Port 25 is opened")
        return public.returnMsg(False,"Cannot connect to port 25 of other services, please contact your hosting provider")

    def download_file(self,args):
        filename = args.filename
        tmp = filename.split('|')
        local_file = tmp[0]
        remote_file = tmp[1].format(download_conf_url="http://node.aapanel.com")
        data = public.readFile("/www/server/panel/plugin/mail_sys/services_file.txt")
        if not data:
            return public.returnMsg(False,"Get source file error!")
        if remote_file not in data or local_file not in data:
            return public.returnMsg(False, "There is no such file!")
        public.ExecShell("wget {remote_file} -O {local_file} -T 10 --no-check-certificate".format(remote_file=remote_file,local_file=local_file))
        return public.returnMsg(True,"Re-download successful")
