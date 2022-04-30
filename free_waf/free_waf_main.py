#coding: utf-8
import sys,os
if sys.version_info[0] == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')
os.chdir('/www/server/panel')
import json,time,public,string,re,hashlib
if __name__ != '__main__':
    from panelAuth import panelAuth

class free_waf_main:
    __path = '/www/server/free_waf/'
    __state = {True:'Open',False:'Close',0:'Stop',1:'Start'}
    __config = None
    __PATH='/www/server/panel/plugin/free_waf/'
    

    def return_site(self, get):
        data = public.M('sites').field('name,path').select()
        ret = {}
        for i in data:
            ret[i['name']] = i['path']
        return public.returnMsg(True, ret)

    def import_data(self, get):
        name = get.s_Name;
        try:
            pdata = json.loads(get.pdata)
        except:
            return public.returnMsg(False, 'Incorrect data format')
        if not pdata: return public.returnMsg(False, 'Incorrect data format')
        iplist = self.__get_rule(name)
        for ips in pdata:
            if ips in iplist: continue;
            iplist.insert(0, ips)
        self.__write_rule(name, iplist)
        return public.returnMsg(True, '导入成功!')

    # 获取规则
    def shell_get_rule(self, get):
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                return data
            except:
                return False
        else:
            return False

    # 查询站点跟目录
    def getdir(self, dir, pc='', lis=[]):
        list = os.listdir(dir)
        for l in list:
            if os.path.isdir(dir + '/' + l):
                lis = self.getdir(dir + '/' + l, pc, lis)
            elif str(l.lower())[-4:] == '.php' and str(dir + '/' + l).find(pc) == -1:
                print (dir + '/' + l)
                lis.append(dir + '/' + l)
        return lis

    # 目录
    def getdir_list(self, get):
        path = get.path
        if os.path.exists(path):
            pc = 'hackcnm'
            rs = self.getdir(path, pc)
            return rs
        else:
            return False

    def scan(self, filelist, rule):
        self.__webshell_data=[]
        import time
        time_data = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        ret = []
        for file in filelist:
            try:
                data = open(file).read()
            except:
                pass
            for r in rule:
                if re.compile(r).findall(data):
                    result = {}
                    result[file] = r
                    self.__webshell_data.append(result)
                    self.send_baota2(file)
                    data = ("%s [!] %s %s  \n" % (time_data, file, r))
                    self.insert_log(data)
        return self.__webshell_data

    def insert_log(self, data):
        public.writeFile(self.__PATH + 'webshell.log', data, 'a+')

    def get_log(self, get):
        path = self.__PATH + 'webshell.log'
        if not os.path.exists(path): return False
        return public.GetNumLines(path, 3000)

    def path_json(self, path, data):
        path_file = str(path).replace('/', '')
        if os.path.exists(path):
            if os.path.exists(self.__PATH + path_file + '.json'):
                try:
                    path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                except:
                    ret = []
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                    path_data = []
                if not path_data: return self.__webshell_data
                for i in self.__webshell_data:
                    for i2 in path_data:
                        if i2 in i:
                            self.__webshell_data.remove(i)
                return self.__webshell_data
            else:
                ret = []
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                path_data = []
                return self.__webshell_data

    def san_dir(self, get):
        file = self.getdir_list(get)
        if not file: return public.returnMsg(False, "Did not find php file")
        rule = self.shell_get_rule(get)
        if not rule: return public.returnMsg(False, "Rule is empty or rule file error")
        self.__webshell_data = []
        result = self.scan(file, rule)
        result = self.path_json(get.path, result)
        return self.__webshell_data

    def xssencode(self, text):
        import cgi
        list = ['`', '~', '&', '<', '>']
        ret = []
        for i in text:
            if i in list:
                i = ''
            ret.append(i)
        str_convert = ''.join(ret)
        text2 = cgi.escape(str_convert, quote=True)
        return text2

    def shell_add_rule(self, get):
        rule = self.xssencode(get.rule)
        ret = []
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    return public.returnMsg(False, 'This rule already exists')
                else:
                    data.append(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, 'Added successfully')
            except:
                return public.returnMsg(False, 'Rule base parsing error')
        else:
            return public.returnMsg(False, 'Rule library file does not exist')

    def shell_del_rule(self, get):
        rule = get.rule
        if os.path.exists(self.__PATH + 'rule.json'):
            try:
                data = json.loads(public.ReadFile(self.__PATH + 'rule.json'))
                if rule in data:
                    data.remove(rule)
                    public.WriteFile(self.__PATH + 'rule.json', json.dumps(data))
                    return public.returnMsg(True, 'successfully deleted')
                else:
                    return public.returnMsg(False, 'This rule does not exist in the rule base')
            except:
                return public.returnMsg(False, 'Rule base parsing error')
        else:
            return public.returnMsg(False, 'Rule library file does not exist')

    def lock_not_webshell(self, get):
        path = get.path
        not_path = get.not_path
        if not os.path.exists(not_path): return public.returnMsg(False, 'file does not exist')
        path_file = str(path).replace('/', '')
        if not os.path.exists(self.__PATH + path_file + '.json'):
            ret = []
            ret.append(not_path)
            public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
        else:
            try:
                path_data = json.loads(public.ReadFile(self.__PATH + path_file + '.json'))
                if not not_path in path_data:
                    path_data.append(not_path)
                    public.WriteFile(self.__PATH + path_file + '.json', json.dumps(path_data))
                    return public.returnMsg(True, 'Added successfully')
                else:
                    return public.returnMsg(False, 'Already exists')
            except:
                ret = []
                ret.append(not_path)
                public.WriteFile(self.__PATH + path_file + '.json', json.dumps(ret))
                return public.returnMsg(True, '11111111')

    def upload_file_url(self,get):
        try:
            if os.path.exists(get.filename):
                data = public.ExecShell('/usr/local/curl/bin/curl https://scanner.baidu.com/enqueue -F archive=@%s' % get.filename)
                data=json.loads(data[0])
                time.sleep(3)
                import requests
                default_headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/67.0.3396.99 Safari/537.36'
                }
                data_list = requests.get(url=data['url'],headers=default_headers, verify=False)
                data2=data_list.json()
                if 'data' in data2[0]:
                    if len(data2[0]['data'])>=1:
                        if 'descr' in data2[0]['data'][0]:
                            if 'WebShell' in data2[0]['data'][0]['descr']:
                                return public.returnMsg(True, 'This file is webshell')
                return public.returnMsg(True, 'No risk detected')
            else:
                return public.returnMsg(False, 'File does not exist')
        except:
            return public.returnMsg(True, 'No risk detected')


    def read_file_md5(self,filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as fp:
                data = fp.read()
            file_md5 = hashlib.md5(data).hexdigest()
            return file_md5
        else:
            return False


    def send_baota2(self,filename):
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_submit'
        pdata={'codetxt':public.ReadFile(filename),'md5':self.read_file_md5(filename),'type':'0','host_ip':public.GetLocalIp(),'size':os.path.getsize(filename)}
        ret = public.httpPost(cloudUrl, pdata)
        return True

    def send_baota(self,get):
        if 'filename' not in get:return public.returnMsg(False, 'Please select the file you need to upload')
        if not os.path.exists(get.filename):return public.returnMsg(False, 'File does not exist')
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_submit'
        pdata={'codetxt':public.ReadFile(get.filename),'md5':self.read_file_md5(get.filename),'type':'0','host_ip':public.GetLocalIp(),'size':os.path.getsize(get.filename)}
        ret = public.httpPost(cloudUrl, pdata)
        if ret=='1':
            return self.check_webshell(get)
        elif ret=='-1':
            return self.check_webshell(get)
        else:
            return public.returnMsg(False, 'System error')

    def check_webshell(self,get):
        if 'filename' not in get: return public.returnMsg(False, 'Please select the file you need to upload')
        if not os.path.exists(get.filename): return public.returnMsg(False, 'File does not exist')
        cloudUrl = 'http://www.bt.cn/api/panel/btwaf_check_file'
        pdata = {'md5': self.read_file_md5(get.filename),'size': os.path.getsize(get.filename)}
        ret = public.httpPost(cloudUrl, pdata)
        if ret == '0':
            return public.returnMsg(True, 'No risk detected')
        elif ret=='1':
            return public.returnMsg(True, 'The file was detected by the system as a webshell! ! ! !')
        elif ret == '-1':
            return public.returnMsg(True, 'The file was not queried, please upload the test.')
        else:
            return public.returnMsg(False, 'System error')

    def __get_md5(self, s):
        m = hashlib.md5()
        m.update(s.encode('utf-8'))
        return m.hexdigest()

    def get_config(self,get):
        config = json.loads(public.readFile(self.__path + 'config.json'));

        if not 'from_data' in config:
            config['from_data'] = True

        if not 'retry_cycle' in config:
            config['retry_cycle'] = 60;
            self.__write_config(config);
        if config['start_time'] == 0:
            config['start_time'] = time.time();
            self.__write_config(config);
        return config
    
    def get_site_config(self,get):
        if not os.path.exists('/www/wwwlogs/free_waf_log'):os.mkdir('/www/wwwlogs/free_waf_log')
        site_config = public.readFile(self.__path + 'site.json')
        data =  self.__check_site(json.loads(site_config))
        if get:
            total_all = self.get_total(None)['sites']
            site_list = []
            for k in data.keys():
                if not k in total_all: total_all[k] = {}
                data[k]['total'] = self.__format_total(total_all[k])
                siteInfo = data[k];
                siteInfo['siteName'] = k;
                site_list.append(siteInfo);
            data = sorted(site_list,key=lambda x : x['log_size'], reverse=True)
        return data
    
    def get_site_config_byname(self,get):
        site_config = self.get_site_config(None);
        config = site_config[get.siteName]
        config['top'] = self.get_config(None)
        return config
    
    def set_open(self,get):
        config = self.get_config(None)
        if config['open']: 
            config['open'] = False
            config['start_time'] = 0
        else:
            config['open'] = True
            config['start_time'] = int(time.time())
        self.__write_log(self.__state[config['open']] + 'Website firewall (WAF)');
        self.__write_config(config)
        return public.returnMsg(True,'Successful setup!');
    
    def set_obj_open(self,get):
        config = self.get_config(None)
        if type(config[get.obj]) != bool:
            if config[get.obj]['open']:
                config[get.obj]['open'] = False
            else:
                config[get.obj]['open'] = True
            self.__write_log(self.__state[config[get.obj]['open']] + '[ '+get.obj+' ] function');
        else:
            if config[get.obj]:
                config[get.obj] = False
            else:
                config[get.obj] = True
            self.__write_log(self.__state[config[get.obj]] + '[ '+get.obj+' ] function');
            
        self.__write_config(config)
        return public.returnMsg(True,'Successful setup!');
    
    def set_site_obj_open(self,get):
        site_config = self.get_site_config(None)
        if type(site_config[get.siteName][get.obj]) != bool:
            if site_config[get.siteName][get.obj]['open']:
                site_config[get.siteName][get.obj]['open'] = False
            else:
                site_config[get.siteName][get.obj]['open'] = True
            self.__write_log(self.__state[site_config[get.siteName][get.obj]['open']] + 'Website [ ' + get.siteName +' ] [ '+get.obj+' ] function');
        else:
            if site_config[get.siteName][get.obj]:
                site_config[get.siteName][get.obj] = False
            else:
                site_config[get.siteName][get.obj] = True
            self.__write_log(self.__state[site_config[get.siteName][get.obj]] + 'Website [ ' + get.siteName +' ] [ '+get.obj+' ] function');
        
        if get.obj == 'drop_abroad': self.__auto_sync_cnlist();
        self.__write_site_config(site_config)
        return public.returnMsg(True,'Successful setup!');
    
    def set_obj_status(self,get):
        config = self.get_config(None)
        config[get.obj]['status'] = int(get.statusCode)
        self.__write_config(config)
        return public.returnMsg(True,'Successful setup!');
    
    def set_cc_conf(self,get):
        config = self.get_config(None)
        config['cc']['cycle'] = int(get.cycle)
        config['cc']['limit'] = int(get.limit)
        config['cc']['endtime'] = int(get.endtime)
        config['cc']['increase'] = (get.increase == '1') | False
        self.__write_config(config)
        self.__write_log('Set the global CC configuration to: After the cumulative request exceeds ' + get.limit + ' in '+get.cycle+' seconds, block ' + get.endtime + ' seconds' + ',enhance:' + get.increase);
        return public.returnMsg(True,'Successful setup!');
    
    def set_site_cc_conf(self,get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['cc']['cycle'] = int(get.cycle)
        site_config[get.siteName]['cc']['limit'] = int(get.limit)
        site_config[get.siteName]['cc']['endtime'] = int(get.endtime)
        site_config[get.siteName]['cc']['increase'] = (get.increase == '1') | False
        self.__write_site_config(site_config)
        self.__write_log('Set the site ['+get.siteName+'] CC configuration to: After the cumulative request exceeds  ' + get.limit + 'in' +get.cycle+' seconds, block ' + get.endtime + ' seconds' + ',enhance:' + get.increase);
        return public.returnMsg(True,'Successful setup!');
    
    def add_cnip(self,get):
        ipn = [self.__format_ip(get.start_ip),self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False,'IP segment format is incorrect');
        if not self.__is_ipn(ipn): return public.returnMsg(False,'The starting IP cannot be greater than the ending IP');
        iplist = self.__get_rule('cn')
        if ipn in iplist: return public.returnMsg(False,'The specified IP segment already exists.!');
        iplist.insert(0,ipn)
        self.__write_rule('cn', iplist)
        self.__write_log('Add the IP segment ['+get.start_ip+'-'+get.end_ip+'] to the domestic IP library');
        return public.returnMsg(True,'Added successfully!');
    
    def remove_cnip(self,get):
        index = int(get.index)
        iplist = self.__get_rule('cn')
        ipn = iplist[index]
        del(iplist[index])
        self.__write_rule('cn', iplist)
        self.__write_log('Remove from domestic IP library [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'successfully deleted!');
    
    def add_ip_white(self,get):
        ipn = [self.__format_ip(get.start_ip),self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False,'IP segment format is incorrect');
        if not self.__is_ipn(ipn): return public.returnMsg(False,'The starting IP cannot be greater than the ending IP');
        iplist = self.__get_rule('ip_white')
        if ipn in iplist: return public.returnMsg(False,'The specified IP segment already exists.!');
        iplist.insert(0,ipn)
        self.__write_rule('ip_white', iplist)
        self.__write_log('Add the IP segment [ '+get.start_ip+'-'+get.end_ip+' ] to the IP whitelist');
        return public.returnMsg(True,'Added successfully!');
    
    def remove_ip_white(self,get):
        index = int(get.index)
        iplist = self.__get_rule('ip_white')
        ipn = iplist[index]
        del(iplist[index])
        self.__write_rule('ip_white', iplist)
        self.__write_log('Remove from IP whitelist [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'successfully deleted!');
    
    def add_ip_black(self,get):
        ipn = [self.__format_ip(get.start_ip),self.__format_ip(get.end_ip)]
        if not ipn[0] or not ipn[1]: return public.returnMsg(False,'IP segment format is incorrect');
        if not self.__is_ipn(ipn): return public.returnMsg(False,'The starting IP cannot be greater than the ending IP');
        iplist = self.__get_rule('ip_black')
        if ipn in iplist: return public.returnMsg(False,'The specified IP segment already exists.!');
        iplist.insert(0,ipn)
        self.__write_rule('ip_black', iplist)
        self.__write_log('Add the IP segment [ '+get.start_ip+'-'+get.end_ip+' ] to the IP blacklist');
        return public.returnMsg(True,'Added successfully!');
    
    def remove_ip_black(self,get):
        index = int(get.index)
        iplist = self.__get_rule('ip_black')
        ipn = iplist[index]
        del(iplist[index])
        self.__write_rule('ip_black', iplist)
        self.__write_log('Remove from IP blacklist [' + '.'.join(map(str,ipn[0])) + '-' + '.'.join(map(str,ipn[1]))+']');
        return public.returnMsg(True,'successfully deleted!');
    
    def add_url_white(self,get):
        url_white = self.__get_rule('url_white')
        url_rule = get.url_rule.strip()
        if get.url_rule in url_white: return public.returnMsg(False,'The URL you added already exists')
        url_white.insert(0,url_rule)
        self.__write_rule('url_white', url_white)
        self.__write_log('Add url rule ['+url_rule+'] to URL whitelist');
        return public.returnMsg(True,'Added successfully!');
    
    def remove_url_white(self,get):
        url_white = self.__get_rule('url_white')
        index = int(get.index)
        url_rule = url_white[index]
        del(url_white[index])
        self.__write_rule('url_white', url_white)
        self.__write_log('Remove URL rules from URL whitelist ['+url_rule+']');
        return public.returnMsg(True,'Successfully deleted!');
    
    def add_url_black(self,get):
        url_white = self.__get_rule('url_black')
        url_rule = get.url_rule.strip()
        if get.url_rule in url_white: return public.returnMsg(False,'The URL you added already exists')
        url_white.insert(0,url_rule)
        self.__write_rule('url_black', url_white)
        self.__write_log('Add url rule ['+url_rule+'] to URL blacklist');
        return public.returnMsg(True,'Added successfully!');
    
    def remove_url_black(self,get):
        url_white = self.__get_rule('url_black')
        index = int(get.index)
        url_rule = url_white[index]
        del(url_white[index])
        self.__write_rule('url_black', url_white)
        self.__write_log('Remove URL rules from the URL blacklist['+url_rule+']');
        return public.returnMsg(True,'Successfully deleted!');
    
    def save_scan_rule(self,get):
        scan_rule = {'header':get.header,'cookie':get.cookie,'args':get.args}
        self.__write_rule('scan_black', scan_rule)
        self.__write_log('Modify scanner filter rules');
        return public.returnMsg(True,'Successful setup')
    
    def set_retry(self,get):
        config = self.get_config(None)
        config['retry'] = int(get.retry)
        config['retry_cycle'] = int(get.retry_cycle)
        config['retry_time'] = int(get.retry_time)
        self.__write_config(config)
        self.__write_log('Set the illegal request tolerance threshold: After the cumulative request exceeds ' + get.retry + ' in '+ get.retry_cycle +'seconds, block ' + get.retry_time + ' seconds');
        return public.returnMsg(True,'Successful setup!');
    
    def set_site_retry(self,get):
        site_config = self.get_site_config(None)
        site_config[get.siteName]['retry'] = int(get.retry)
        site_config[get.siteName]['retry_cycle'] = int(get.retry_cycle)
        site_config[get.siteName]['retry_time'] = int(get.retry_time)
        self.__write_site_config(site_config)
        self.__write_log('Set the website ['+get.siteName+'] illegal request tolerance threshold: After the cumulative request exceeds ' + get.retry + ' in ' + get.retry_cycle +' seconds, block ' + get.retry_time + ' seconds');
        return public.returnMsg(True,'Successful setup!');
    
    def set_site_cdn_state(self,get):
        site_config = self.get_site_config(None)
        if site_config[get.siteName]['cdn']:
            site_config[get.siteName]['cdn'] = False
        else:
            site_config[get.siteName]['cdn'] = True
        self.__write_site_config(site_config)
        self.__write_log(self.__state[site_config[get.siteName]['cdn']] + 'Site [ '+get.siteName+' ] CDN mode');
        return public.returnMsg(True,'Successful setup!');
    
    def get_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName]['cdn_header']
    
    def add_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,'The request header you added already exists!');
        site_config[get.siteName]['cdn_header'].append(get.cdn_header)
        self.__write_site_config(site_config)
        self.__write_log('Add site [ '+get.siteName+'] CDN-Header [ '+get.cdn_header+' ]');
        return public.returnMsg(True,'Added successfully!');
    
    def remove_site_cdn_header(self,get):
        site_config = self.get_site_config(None)
        get.cdn_header = get.cdn_header.strip().lower();
        if not get.cdn_header in site_config[get.siteName]['cdn_header']: return public.returnMsg(False,'The request header you added already exists!');
        for i in range(len(site_config[get.siteName]['cdn_header'])):
            if get.cdn_header == site_config[get.siteName]['cdn_header'][i]:
                self.__write_log('Delete site [ '+get.siteName+' ] CDN-Header [ '+site_config[get.siteName]['cdn_header'][i]+' ]');
                del(site_config[get.siteName]['cdn_header'][i])
                break;
        self.__write_site_config(site_config)
        return public.returnMsg(True,'Successfully deleted!');
    
    def get_site_rule(self,get):
        site_config = self.get_site_config(None)
        return site_config[get.siteName][get.ruleName]
    
    def add_site_rule(self,get):
        site_config = self.get_site_config(None)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False,'The specified rule does not exist!');
        mt = type(site_config[get.siteName][get.ruleName])
        if mt == bool: return public.returnMsg(False,'The specified rule does not exist!');
        if mt == str: site_config[get.siteName][get.ruleName] = get.ruleValue
        if mt == list:
            if get.ruleName == 'url_rule' or get.ruleName == 'url_tell':
                for ruleInfo in site_config[get.siteName][get.ruleName]:
                    if ruleInfo[0] == get.ruleUri: return public.returnMsg(False,'The specified URI already exists!');
                tmp = []
                tmp.append(get.ruleUri)
                tmp.append(get.ruleValue)
                if get.ruleName == 'url_tell': 
                    self.__write_log('Add the site [ '+get.siteName+' ] URI [ '+get.ruleUri+' ] protection rule, parameter [ '+get.ruleValue+' ], parameter value [ '+get.rulePass+' ]');
                    tmp.append(get.rulePass)
                else:
                    self.__write_log('Add site [ '+get.siteName+' ] URI [ '+get.ruleUri+' ] filter rule [ '+get.ruleValue+' ]');
                site_config[get.siteName][get.ruleName].insert(0,tmp)
            else:
                if get.ruleValue in site_config[get.siteName][get.ruleName]: return public.returnMsg(False,'The specified rule already exists!');
                site_config[get.siteName][get.ruleName].insert(0,get.ruleValue)
                self.__write_log('Add site [ '+get.siteName+'  [ '+get.ruleName+' ] filter rule [ '+get.ruleValue+' ]');
        self.__write_site_config(site_config)
        return public.returnMsg(True,'Added successfully!');
    
    
    def remove_site_rule(self,get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if not get.ruleName in site_config[get.siteName]: return public.returnMsg(False,'The specified rule already exists!');
        site_rule = site_config[get.siteName][get.ruleName][index]
        del(site_config[get.siteName][get.ruleName][index])
        self.__write_site_config(site_config)
        self.__write_log('Delete the site [ '+get.siteName+' ] [ '+get.ruleName+' ] filter rule [ '+json.dumps(site_rule)+' ]');
        return public.returnMsg(True,'Successfully deleted!');
    
    def get_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        if not rule: return [];
        return rule
    
    def add_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        ruleValue = [1, get.ruleValue.strip(),get.ps,1]
        for ru in rule:
            if ru[1] == ruleValue[1]: return public.returnMsg(False,'The specified rule already exists. Do not add it repeatedly.');
        rule.append(ruleValue)
        self.__write_rule(get.ruleName, rule)
        self.__write_log('Add global rules [ '+get.ruleName+' ] [ '+get.ps+' ]');
        return public.returnMsg(True,'Added successfully!');
    
    def remove_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        ps = rule[index][2]
        del(rule[index])
        self.__write_rule(get.ruleName, rule)
        self.__write_log('Delete global rule [ '+get.ruleName+' ] [ '+ps+' ]');
        return public.returnMsg(True,'Successfully deleted!');
    
    def modify_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        rule[index][1] = get.ruleBody
        rule[index][2] = get.rulePs
        self.__write_rule(get.ruleName, rule)
        self.__write_log('Modify the global rule [ '+get.ruleName+' ] [ '+get.rulePs+' ]');
        return public.returnMsg(True,'Successfully modified!');
    
    def set_rule_state(self,get):
        rule = self.__get_rule(get.ruleName)
        index = int(get.index)
        if rule[index][0] == 0:
            rule[index][0] = 1;
        else:
            rule[index][0] = 0;
        self.__write_rule(get.ruleName, rule)
        self.__write_log(self.__state[rule[index][0]] + 'Global rules [ '+get.ruleName+' ] [ '+rule[index][2]+' ]');
        return public.returnMsg(True,'Successful setup!');
    
    def get_site_disable_rule(self,get):
        rule = self.__get_rule(get.ruleName)
        site_config = self.get_site_config(None)
        site_rule = site_config[get.siteName]['disable_rule'][get.ruleName]
        for i in range(len(rule)):
            if rule[i][0] == 0: rule[i][0] = -1;
            if i in site_rule: rule[i][0] = 0;
        return rule;
    
    def set_site_disable_rule(self,get):
        site_config = self.get_site_config(None)
        index = int(get.index)
        if index in site_config[get.siteName]['disable_rule'][get.ruleName]:
            for i in range(len(site_config[get.siteName]['disable_rule'][get.ruleName])):
                if index == site_config[get.siteName]['disable_rule'][get.ruleName][i]:
                    del(site_config[get.siteName]['disable_rule'][get.ruleName][i])
                    break
        else:
            site_config[get.siteName]['disable_rule'][get.ruleName].append(index)
        self.__write_log('Set the site [ '+get.siteName+' ] to apply the rule [ '+get.ruleName+' ] status');
        self.__write_site_config(site_config)
        return public.returnMsg(True,'Successful setup!');
    
    def get_safe_logs(self,get):
        try:
            import cgi
            pythonV = sys.version_info[0]
            if 'drop_ip' in get:
                path = '/www/server/free_waf/drop_ip.log'
                num = 14
            else:
                path = '/www/wwwlogs/free_waf_log/' + get.siteName + '_' + get.toDate + '.log'
                num = 10
            if not os.path.exists(path): return []
            p = 1
            if 'p' in get:
                p = int(get.p)
            start_line = (p - 1) * num
            count = start_line + num
            fp = open(path, 'rb')
            buf = ""
            try:
                fp.seek(-1, 2)
            except:
                return []
            if fp.read(1) == "\n": fp.seek(-1, 2)
            data = []
            b = True
            n = 0
            c = 0
            while c < count:
                while True:
                    newline_pos = str.rfind(buf, "\n")
                    pos = fp.tell()
                    if newline_pos != -1:
                        if n >= start_line:
                            line = buf[newline_pos + 1:]
                            if line:
                                try:
                                    tmp_data = json.loads(cgi.escape(line))
                                    for i in range(len(tmp_data)):
                                        if i == 7:
                                            tmp_data[i] = str(tmp_data[i]).replace('&amp;', '&').replace('&lt;',
                                                                                                         '<').replace(
                                                '&gt;', '>')
                                        else:
                                            tmp_data[i] = cgi.escape(str(tmp_data[i]), True)
                                    data.append(tmp_data)
                                except:
                                    c -= 1
                                    n -= 1
                                    pass
                            else:
                                c -= 1
                                n -= 1
                        buf = buf[:newline_pos]
                        n += 1
                        c += 1
                        break
                    else:
                        if pos == 0:
                            b = False
                            break
                        to_read = min(4096, pos)
                        fp.seek(-to_read, 1)
                        t_buf = fp.read(to_read)
                        if pythonV == 3: t_buf = t_buf.decode('utf-8', errors="ignore")
                        buf = t_buf + buf
                        fp.seek(-to_read, 1)
                        if pos - to_read == 0:
                            buf = "\n" + buf
                if not b: break
            fp.close()
            if 'drop_ip' in get:
                drop_iplist = self.get_waf_drop_ip(None)
                stime = time.time()
                setss = []
                for i in range(len(data)):
                    if (float(stime) - float(data[i][0])) < float(data[i][4]) and not data[i][1] in setss:
                        setss.append(data[i][1])
                        data[i].append(data[i][1] in drop_iplist)
                    else:
                        data[i].append(False)
        except:
            return public.get_error_info()
            data = []
        return data
    
    def get_logs_list(self,get):
        path = '/www/wwwlogs/free_waf_log/'
        sfind = get.siteName + '_'
        data = []
        for fname in os.listdir(path):
            if fname.find(sfind) != 0: continue;
            tmp = fname.replace(sfind,'').replace('.log','')
            data.append(tmp)
        return sorted(data,reverse=True);
    
    def get_waf_drop_ip(self,get):
        try:
            return json.loads(public.httpGet('http://127.0.0.1/get_btwaf_drop_ip'))
        except:
            return [];
    def remove_waf_drop_ip(self,get):
        try:
            data = json.loads(public.httpGet('http://127.0.0.1/remove_btwaf_drop_ip?ip=' + get.ip))
            self.__write_log('Unpack IP from the firewall [ '+get.ip+' ]');
            return data
        except:
            return public.returnMsg(False,'Failed to get data');
    
    def clean_waf_drop_ip(self,get):
        try:
            self.__write_log('Unblock all IPs from the firewall');
            return json.loads(public.httpGet('http://127.0.0.1/clean_btwaf_drop_ip'))
        except:
            return public.returnMsg(False,'Failed to get data');
        

    def get_gl_logs(self, get):
        import page
        page = page.Page();
        count = public.M('logs').where('type=?', (u'Nginx free firewall',)).count();
        limit = 12;
        info = {}
        info['count'] = count
        info['row'] = limit
        info['p'] = 1
        if hasattr(get, 'p'):
            info['p'] = int(get['p'])
        info['uri'] = get
        info['return_js'] = ''
        if hasattr(get, 'tojs'):
            info['return_js'] = get.tojs

        data = {}

        # 获取分页数据
        data['page'] = page.GetPage(info, '1,2,3,4,5,8');
        data['data'] = public.M('logs').where('type=?', (u'Nginx free firewall',)).order('id desc').limit(
            str(page.SHIFT) + ',' + str(page.ROW)).field('log,addtime').select();
        return data;

            
    def get_total(self,get):
        try:
            total = json.loads(public.readFile(self.__path + 'total.json'))
        except:
            total = {"rules":{"user_agent":0,"cookie":0,"post":0,"args":0,"url":0,"cc":0},"sites":{},"total":0}
            self.__write_total(total);
        if type(total['rules']) != dict:
            new_rules = {}
            for rule in total['rules']:
                new_rules[rule['key']] = rule['value'];
            total['rules'] = new_rules;
            self.__write_total(total);
        total['rules'] = self.__format_total(total['rules'])
        return total;
    
    def __format_total(self,total):
        total['get'] = 0;
        if 'args' in total:
            total['get'] += total['args'];
            del(total['args'])
        if 'url' in total:
            total['get'] += total['url'];
            del(total['url'])
        cnkey = [
                 ['post',u'POST Penetration'],
                 ['get',u'GET Penetration'],
                 ['cc',u"CC Attack"],
                 ['user_agent',u'Malicious UA'],
                 ['cookie',u'Cookie Penetration'],
                 ['scan',u'Malicious Scan'],
                 ['head',u'Malicious Request HEAD'],
                 ['url_rule',u'URI custom interception'],
                 ['url_tell',u'URI Protection'],
                 ['disable_upload_ext',u'Malicious file upload'],
                 ['disable_ext',u'Prohibited extension'],
                 ['disable_php_path',u'Prohibit PHP scripts']
                 ]
        data = []
        for ck in cnkey:
            tmp = {}
            tmp['name'] = ck[1]
            tmp['key'] = ck[0]
            tmp['value'] = 0;
            if ck[0] in total: tmp['value'] = total[ck[0]]
            data.append(tmp)
        return data
    
    def get_total_all(self,get):
        self.__check_cjson();
        nginxconf = '/www/server/nginx/conf/nginx.conf';
        if not os.path.exists(nginxconf): return public.returnMsg(False,'Only support nginx server');
        if public.readFile(nginxconf).find('luawaf.conf') == -1: return public.returnMsg(False,'Currently nginx does not support firewall, please reinstall nginx');
        data = {}
        data['total'] = self.get_total(None)
        del(data['total']['sites'])
        data['drop_ip'] = []
        data['open'] = self.get_config(None)['open']
        conf = self.get_config(None)
        data['safe_day'] = 0
        if 'start_time' in conf:
            if conf['start_time'] != 0: data['safe_day'] = int((time.time() - conf['start_time']) / 86400)
        self.__write_site_domains()
        return data
    
    def __write_site_domains(self):
        sites = public.M('sites').field('name,id').select();
        my_domains = []
        for my_site in sites:
            tmp = {}
            tmp['name'] = my_site['name']
            tmp_domains = public.M('domain').where('pid=?',(my_site['id'],)).field('name').select()
            tmp['domains'] = []
            for domain in tmp_domains:
                tmp['domains'].append(domain['name'])
            binding_domains = public.M('binding').where('pid=?',(my_site['id'],)).field('domain').select()
            for domain in binding_domains:
                tmp['domains'].append(domain['domain'])
            my_domains.append(tmp)
        public.writeFile(self.__path + '/domains.json',json.dumps(my_domains))
        return my_domains
    
    
    #设置自动同步
    def __auto_sync_cnlist(self):      
        return True
        

    def __get_rule(self,ruleName):
        path = self.__path + 'rule/' + ruleName + '.json';
        rules = public.readFile(path)
        if not rules: return False
        return json.loads(rules)
    
    def __write_rule(self,ruleName,rule):
        path = self.__path + 'rule/' + ruleName + '.json';
        public.writeFile(path,json.dumps(rule))
        public.serviceReload();
    
    def __check_site(self,site_config):
        sites = public.M('sites').field('name').select();
        siteNames = []
        n = 0
        for siteInfo in sites:
            siteNames.append(siteInfo['name'])
            if siteInfo['name'] in site_config: continue
            site_config[siteInfo['name']] = self.__get_site_conf()
            n += 1
        old_site_config = site_config.copy()
        for sn in site_config.keys():
            if sn in siteNames: 
                if not 'retry_cycle' in site_config[sn]:
                    site_config[sn]['retry_cycle'] = 60;
                    n += 1;
                continue
            del(old_site_config[sn])
            self.__remove_log_file(sn)
            n += 1
        
        if n > 0: 
            site_config = old_site_config.copy()
            self.__write_site_config(site_config)
        
        config = self.get_config(None)
        logList = os.listdir(config['logs_path'])
        mday = time.strftime('%Y-%m-%d',time.localtime());
        for sn in siteNames:
            site_config[sn]['log_size'] = 0;
            day_log = config['logs_path'] + '/' + sn + '_' + mday + '.log';
            if os.path.exists(day_log):
                site_config[sn]['log_size'] = os.path.getsize(day_log)
            
            tmp = []
            for logName in logList:
                if logName.find(sn + '_') != 0: continue;
                tmp.append(logName)
            
            length = len(tmp) - config['log_save'];
            if length > 0:
                tmp = sorted(tmp)
                for i in range(length):
                    filename = config['logs_path'] + '/' + tmp[i];
                    if not os.path.exists(filename): continue
                    os.remove(filename)
        return site_config;
    
    def __is_ipn(self,ipn):
        for i in range(4):
            if ipn[0][i] == ipn[1][i]: continue;
            if ipn[0][i] < ipn[1][i]: break;
            return False
        return True
    
    def __format_ip(self,ip):
        tmp = ip.split('.')
        if len(tmp) < 4: return False
        tmp[0] = int(tmp[0])
        tmp[1] = int(tmp[1])
        tmp[2] = int(tmp[2])
        tmp[3] = int(tmp[3])
        return tmp;
    
    def __get_site_conf(self):
        if not self.__config: self.__config = self.get_config(None)
        conf = {
            'open': True,
            'project': '',
            'log': True,
            'cdn': False,
            'cdn_header': ['x-forwarded-for', 'x-real-ip'],
            'retry': self.__config['retry'],
            'retry_cycle': self.__config['retry_cycle'],
            'retry_time': self.__config['retry_time'],
            'disable_php_path': ['^/upload/', '^/static/'],
            'disable_path': [],
            'disable_ext': [],
            'disable_upload_ext': ['php', 'jsp'],
            'url_white': [],
            'url_rule': [],
            'url_tell': [],
            'disable_rule': {
                'url': [],
                'post': [],
                'args': [],
                'cookie': [],
                'user_agent': []
            },
            'cc': {
                'open': self.__config['cc']['open'],
                'cycle': self.__config['cc']['cycle'],
                'limit': self.__config['cc']['limit'],
                'endtime': self.__config['cc']['endtime']
            },
            'get': self.__config['get']['open'],
            'post': self.__config['post']['open'],
            'cookie': self.__config['cookie']['open'],
            'user-agent': self.__config['user-agent']['open'],
            'scan': self.__config['scan']['open'],
            'drop_abroad': False
        }
        return conf
    
    def sync_cnlist(self,get):
        if not get:
            self.get_config(None)
            self.get_site_config(None)
        rcnlist = public.httpGet(public.get_url() + '/cnlist.json')
        if not rcnlist: return public.returnMsg(False,'Connection to the cloud failed')
        cloudList = json.loads(rcnlist)
        cnlist = self.__get_rule('cn')
        n = 0
        for ipd in cloudList:
            if ipd in cnlist: continue;
            cnlist.append(ipd)
            n += 1
        self.__write_rule('cn', cnlist)
        if get: return public.returnMsg(True,'The synchronization is successful, this time add a total of ' + str(n) + ' IP segments')
        
    def __remove_log_file(self,siteName):
        public.ExecShell('/www/wwwlogs/free_waf/' + siteName + '_*.log')
        total = json.loads(public.readFile(self.__path + 'total.json'))
        if siteName in total['sites']:
            del(total['sites'][siteName])
            self.__write_total(total)
        return True
            
    def __write_total(self,total):
        return public.writeFile(self.__path + 'total.json',json.dumps(total))

    
    def __write_config(self,config):
        public.writeFile(self.__path + 'config.json',json.dumps(config))
        public.serviceReload();
    
    def __write_site_config(self,site_config):
        public.writeFile(self.__path + 'site.json',json.dumps(site_config))
        public.serviceReload();
    
    def __write_log(self,msg):
        public.WriteLog('Nginx free firewall',msg)
        
    def __check_cjson(self):
        cjson = '/usr/local/lib/lua/5.1/cjson.so'
        if os.path.exists(cjson): 
            if os.path.exists('/usr/lib64/lua/5.1'):
                if not os.path.exists('/usr/lib64/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so");
            if os.path.exists('/usr/lib/lua/5.1'):
                if not os.path.exists('/usr/lib/lua/5.1/cjson.so'):
                    public.ExecShell("ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so");
            return True
        
        c = '''wget -O lua-cjson-2.1.0.tar.gz http://download.bt.cn/install/src/lua-cjson-2.1.0.tar.gz -T 20
tar xvf lua-cjson-2.1.0.tar.gz
rm -f lua-cjson-2.1.0.tar.gz
cd lua-cjson-2.1.0
make
make install
cd ..
rm -rf lua-cjson-2.1.0
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so
ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so
/etc/init.d/nginx reload
'''
        public.writeFile('/root/install_cjson.sh',c)
        public.ExecShell('cd /root && bash install_cjson.sh')
        return True
    