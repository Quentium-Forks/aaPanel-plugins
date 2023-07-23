#coding: utf-8
#-------------------------------------------------------------------
# 宝塔Linux面板
#-------------------------------------------------------------------
# Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
#-------------------------------------------------------------------
# Author: hwliang<hwl@bt.cn>
#-------------------------------------------------------------------

#------------------------------
# Node.js版本管理器
#------------------------------


import os,public,json,time,sys
from BTPanel import cache
dict_obj = public.dict_obj()
class nodejs_main:
    _setup_path = '/www/server'
    _plugin_path = _setup_path + '/panel/plugin/nodejs'
    _node_url = 'https://nodejs.org/dist'
    _list_file = _plugin_path + '/version_list.json'
    _nodejs_path = _setup_path + '/nodejs'
    _show_config = _plugin_path + '/show.pl'
    _exec_log = _plugin_path + '/exec.log'
    _registry = None
    _registry_file = _plugin_path + '/registry.pl'

    def __init__(self):
        self._registry = self.get_registry_url()

    def get_registry_url(self,get = None):
        '''
            @name 获取registry源
            @author hwliang<2021-08-03>
            @param get<dict_obj>
            @return string
        '''
        if self._registry: return self._registry
        if not os.path.exists(self._registry_file): return  'https://registry.npmjs.org/' #'https://registry.npm.taobao.org/'
        return public.readFile(self._registry_file)


    def get_glibc_version(self):
        '''
            @name 获取glibc版本号
            @author hwliang
            @return float
        '''
        try:
            result = public.ExecShell("ldd  --version|grep ldd")
            if not result[0]: return 2.17
            return float(result[0].split()[-1])
        except:
            return 2.17


    def set_registry_url(self,get):
        '''
            @name 设置registry源
            @author hwliang<2021-08-03>
            @param get<dict>{
                registry:<str>registry源
            }
            @return dict
        '''
        registry = get['registry']
        self._registry = registry
        public.writeFile(self._registry_file,registry)
        return self.return_data(True,'Setup successfully!')


    def set_nvm_env(self):
        '''
            @name 设置nvm环境变量
            @author hwliang<2021-08-04>
            @return bool
        '''
        nvm_dir = '/www/server/nvm'
        if not os.path.exists(nvm_dir):
            return False
        bashrc_file = '/root/.bashrc'
        if not os.path.exists(bashrc_file): return False
        bashrc_content = public.readFile(bashrc_file)
        if 'NVM_DIR' in bashrc_content: return True
        bashrc_content += '''export NVM_DIR="/www/server/nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm
[ -s "$NVM_DIR/bash_completion" ] && \. "$NVM_DIR/bash_completion"  # This loads nvm bash_completion
'''
        public.writeFile(bashrc_file,bashrc_content)
        return True


    def check_nvm_env(self,get = None):
        '''
            @name 检测NVM环境变量
            @author hwliang<2021-08-04>
            @param get<dict_obj>
            @return bool
        '''

        bashrc_file = '/root/.bashrc'
        if not os.path.exists(bashrc_file): return False
        bashrc_content = public.readFile(bashrc_file)
        if 'NVM_DIR' in bashrc_content: return True
        return False


    def clear_nvm_env(self,get = None):
        '''
            @name 清理NVM环境变量
            @author hwliang<2021-08-04>
            @param get<dict_obj>
            @return dict
        '''
        bashrc_file = '/root/.bashrc'
        public.ExecShell("sed -i '/NVM_DIR/d' {}".format(bashrc_file))
        public.ExecShell("sed -i '/NODE_PATH/d' {}".format(bashrc_file))
        return self.return_data(True,'Cleaned up successfully!')
        

    def get_online_version_list(self,get = dict_obj):
        '''
            @name 获取在线版本列表
            @author hwliang<2021-07-29>
            @param get<dict_obj>{
                is_lts:<str>是否使用LTS,默认为0  1.是 0.否    [可选]
                force:<str>是否强制从云端获取,默认为0 1.是 0.否 [可选]
                is_hide:<str>是否隐藏,默认为0 1.是 0.否 [可选]
            }
            @return list
        '''
        version_list = []
        is_local = True

        # 本地版本列表超过24小时就强制从云端获取
        if os.path.exists(self._list_file):
            stat = os.stat(self._list_file)
            if stat.st_mtime + 86400 < time.time():
                get['force'] = '1'

        is_http  = 's' in get
        if not 'force' in get: get.force = '0'
        # 是否从云端获取列表
        if not os.path.exists(self._list_file) or get['force'] == '1':
            try:
                url = "{}/index.json".format(self._node_url)
                http_result = json.loads(public.httpGet(url,timeout=5))
                if os.path.exists(self._list_file): os.remove(self._list_file)
                public.writeFile(self._list_file,json.dumps(http_result))
                is_local = False
            except:
                is_local = True
                return public.get_error_info()

        # 是否从本地读取列表
        if is_local:
            try:
                public.readFile(self._list_file)
                http_result = json.loads(public.readFile(self._list_file))
            except:
                if os.path.exists(self._list_file):
                    os.remove(self._list_file)
                http_result = []

        if 'show_type' in get:
            public.writeFile(self._show_config,get.show_type)
        
        show_type = public.readFile(self._show_config)
        if show_type is False: show_type = '2'
        lts_v = None
        sync_vs = []

        # 获取当前OS信息
        fname = self._get_version_filename()
        namex = fname.replace('.tar.gz','')
        registry_url = self.get_registry_url()

        cli_version = self.get_default_env(None)
        glibc_version = self.get_glibc_version()
        for v in http_result:
            # 移除不支持此平台的版本
            if not namex in v['files']: continue

            if glibc_version <= 2.17:
                node_version = int(v['version'].replace('v','').split('.')[0])
                if node_version >= 18: continue

            # 是否已安装？
            nodejs_bin = "{}/{}/bin/node".format(self._nodejs_path , v['version'])
            v['setup'] = 1 if os.path.exists(nodejs_bin) else 0
            v['show_type'] = show_type

            # 只显示LTS版本？
            if show_type == '1' and not v['setup']:
                if not v['lts']: continue

            # 隐藏不常用版本
            if not v['setup'] and show_type  != '0':
                # 隐藏早期版本
                # if v['npm'][0] in ['2','3']: continue

                # 只显示稳定版和最新测试版本
                if lts_v and not v['lts']: continue
                if v['lts']: lts_v = v['lts']

                # 有多个子版本的情况下只显示最新子版本
                last_vs = v['version'].split('.')[:-1]
                if last_vs in sync_vs: continue
                sync_vs.append(last_vs)

            if cli_version == v['version']:
                v['is_default'] = 1


            if v['setup']:
                nodejs_prefix = "{}/{}/".format(self._nodejs_path,v['version'])
                etc_path = "{}/etc".format(nodejs_prefix)
                if not os.path.exists(etc_path): os.makedirs(etc_path)
                npmrc_file = "{}/npmrc".format(etc_path,v['version'])
                if not os.path.exists(npmrc_file):
                    public.writeFile(npmrc_file,self.get_npmrc_info(v['version']))

                npm_version = self.get_module_version(v['version'],'npm')
                if npm_version: v['npm'] = npm_version

            v['registry'] = registry_url
            if is_http: 
                v.pop('files')
            version_list.append(v)

        return sorted(version_list,key=lambda x:x['setup'],reverse=True)


    def get_module_version(self,version,mod_name):
        '''
            @name 获取模块版本
            @author hwliang<2021-08-04>
            @param version<str> Node版本
            @param mod_name:<str>模块名
            @return str
        '''

        # 获取模块版本
        package_file = "{}/{}/lib/node_modules/{}/package.json".format(self._nodejs_path,version,mod_name)
        if not os.path.exists(package_file): return False
        package_info = json.loads(public.readFile(package_file))
        return package_info['version']


    def get_shell_env(self,version):
        '''
            @name 获取命令行前置环境变量
            @author hwliang<2021-08-03>
            @param version<string> 版本号
            @return string
        '''
        prefix = "{}/{}/".format(self._nodejs_path,version)
        cache_path = "{}/cache".format(prefix)
        npm_bin = "{}/bin/npm".format(prefix)
        node_bin_path = "{}/{}/bin".format(self._nodejs_path,version)
        yarn_bin = "{}/bin/yarn".format(prefix)
        yarn_config = ''
        if os.path.exists(yarn_bin):
            yarn_config = '{} config set registry {}'.format(yarn_bin,self._registry)

        env_str = '''PATH={NODE_BIN_PATH}:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
export HOME=/root
export NODE_PATH="{PREFIX}etc/node_modules"
{NPM_BIN} config set registry {REGISTRY}
{NPM_BIN} config set prefix {PREFIX}
{NPM_BIN} config set cache {CACHE}
{YARN_CONFIG}
'''.format(NODE_BIN_PATH = node_bin_path,PREFIX=prefix,REGISTRY=self._registry,CACHE=cache_path,NPM_BIN=npm_bin,YARN_CONFIG = yarn_config)

        return env_str


    def get_npmrc_info(self,version):
        '''
            @name 获取指定版本的npmrc默认信息
            @author hwliang<2021-08-03>
            @param version<str> 版本号
            @return string
        '''
        prefix = "{}/{}/".format(self._nodejs_path,version)
        registry = self._registry
        cache_path = "{}/cache/".format(self._nodejs_path)
        if not os.path.exists(cache_path): os.makedirs(cache_path)
        init_module = "{}etc/init-module.js".format(prefix)
        npmrc_body = '''prefix = {}
registry = {}
cache = {}
init.module = {}
'''.format(prefix,registry,cache_path,init_module)
        return npmrc_body
        
    def return_data(self,status,data = {},status_code=None,error_msg = None):
        '''
            @name 格式化响应内容
            @author hwliang<2021-07-14>
            @param status<bool> 状态
            @param data<mixed> 响应数据
            @param status_code<int> 状态码
            @param error_msg<string> 错误消息内容
            @return dict

        '''
        if status_code is None:
            status_code = 1 if status else 0
        if error_msg is None:
            error_msg = '' if status else 'unknown mistake'
        
        result = {
                    'status':status,
                    "status_code":status_code,
                    'error_msg':str(error_msg),
                    'data':data
                }
        return result

    
    def get_version_info(self,get = dict_obj):
        '''
            @name 获取版本信息
            @author hwliang<2021-07-29>
            @param get<dict_obj>{
                version:<str>版本号
            }
            @return dict
        '''
        version = get['version']
        version_list = self.get_online_version_list()
        for v in version_list:
            if v['version'] == version:
                return self.return_data(True,v)
        return self.return_data(False,error_msg='Version not found')

    def _get_version_filename(self):
        '''
            @name 获取适用于当前系统的版本文件名
            @author hwliang<2021-07-29>
            @return string
        '''
        uname = os.uname()
        if sys.version_info.major == 2:
            sysname = uname[0].lower()
            machine = uname[-1]
            uname = public.dict_obj()
            uname.sysname = sysname
            uname.machine = machine
        else:
            sysname = uname.sysname.lower()

        ext = '.tar.gz'
        if uname.machine == 'x86_64':
            return '{}-x64{}'.format(sysname,ext)
        elif uname.machine == 'i686':
            return '{}-x86{}'.format(sysname,ext)
        elif uname.machine == 'aarch64':
            return '{}-arm64{}'.format(sysname,ext)
        elif uname.machine == 'armv7l':
            return '{}-armv71{}'.format(sysname,ext)
        elif uname.machine == 'armv6l':
            return '{}-armv61{}'.format(sysname,ext)
        elif uname.machine == 'armv5l':
            return '{}-armv51{}'.format(sysname,ext)
        elif uname.machine == 'armv4l':
            return '{}-armv41{}'.format(sysname,ext)
        elif uname.machine == 'armv3l':
            return '{}-armv31{}'.format(sysname,ext)
        elif uname.machine == 'armv2l':
            return '{}-armv21{}'.format(sysname,ext)
        elif uname.machine == 'mips':
            return '{}-mips{}'.format(sysname,ext)
        elif uname.machine == 'mips64':
            return '{}-mips64{}'.format(sysname,ext)
        elif uname.machine == 'ppc64':
            return '{}-ppc64{}'.format(sysname,ext)
        elif uname.machine == 'ppc64le':
            return '{}-ppc64le{}'.format(sysname,ext)
        elif uname.machine == 's390x':
            return '{}-s390x{}'.format(sysname,ext)
        elif uname.machine == 'sparc64':
            return '{}-sparc64{}'.format(sysname,ext)
        elif uname.machine == 'sparc':
            return '{}-sparc{}'.format(sysname,ext)
        else:
            return ''


    def __download_file(self,url,save_file):
        '''
            @name 下载文件
            @author hwliang<2021-06-21>
            @param url<string> URL地址
            @param save_file<string> 保存路径
            @return bool
        '''
        pkey = '{}_pre'.format('node_downlaod')
        import requests
        import requests.packages.urllib3.util.connection as urllib3_conn
        from requests.packages.urllib3.exceptions import InsecureRequestWarning
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        old_family = urllib3_conn.allowed_gai_family
        import socket
        urllib3_conn.allowed_gai_family = lambda: socket.AF_INET
        try:
            download_res = requests.get(url,headers=public.get_requests_headers(),timeout=30,stream=True)
        except Exception as ex:
            urllib3_conn.allowed_gai_family = lambda: socket.AF_INET6
            try:
                download_res = requests.get(url,headers=public.get_requests_headers(),timeout=30,stream=True)
            except:
                return False
            finally:
                urllib3_conn.allowed_gai_family = old_family
        finally:
            urllib3_conn.allowed_gai_family = old_family

        headers_total_size = 63891812
        is_content_length = False
        if 'Content-Length' in download_res.headers.keys(): # 没有反回长度？
            headers_total_size = int(download_res.headers['Content-Length'])
            is_content_length = True

        res_down_size = 0
        res_chunk_size = 8192
        last_time = time.time()
        with open(save_file,'wb+') as with_res_f:
            for download_chunk in download_res.iter_content(chunk_size=res_chunk_size):
                if download_chunk: 
                    with_res_f.write(download_chunk)
                    speed_last_size = len(download_chunk)
                    res_down_size += speed_last_size
                    res_start_time = time.time()
                    res_timeout = (res_start_time - last_time)
                    res_sec_speed = int(res_down_size / res_timeout)
                    pre_text = '{}/{}/{}'.format(res_down_size,headers_total_size,res_sec_speed)
                    cache.set(pkey,pre_text,3600)
            with_res_f.close()
        if cache.get(pkey): cache.delete(pkey)
        if not os.path.exists(save_file): return False
        if is_content_length: # 下载完成后，检查文件大小是否和header里面的一致
            if os.path.getsize(save_file) < headers_total_size:
                os.remove(save_file)
                return False
        return True

    def get_install_speed(self,get):
        '''
            @name 取插件下载进度
            @author hwliang<2021-06-21>
            @param get<dict_obj>
            @return dict
        '''
        pkey = '{}_pre'.format('node_downlaod')
        pre_text = cache.get(pkey)
        if not pre_text:
            return public.returnMsg(False,'The specified progress information does not exist!')
        result = { "status": True }
        pre_tmp = pre_text.split('/')
        result['down_size'],result['total_size'] = (int(pre_tmp[0]),int(pre_tmp[1]))
        result['down_pre'] = round(result['down_size'] / result['total_size'] * 100,1)
        result['sec_speed'] = int(float(pre_tmp[2]))
        result['need_time'] = int((result['total_size'] - result['down_size']) / result['sec_speed'])
        return result

    def install_nodejs(self,get):
        '''
            @name 下载并安装指定版本的nodejs
            @author hwliang<2021-07-29>
            @param get<dict_obj>{
                version: string<版本号>
            }
            @return dict
        '''

        # 安装前的检查
        version = get['version']
        version_info = self.get_version_info(get)
        if not version_info['status']: return version_info
        version_info = version_info['data']
        if version_info['setup']: return self.return_data(False,'',error_msg='This version is already installed')
        if not os.path.exists(self._nodejs_path): os.makedirs(self._nodejs_path, 384)
        fname = self._get_version_filename()
        namex = fname.replace('.tar.gz','')
        if not namex in version_info['files']:
            return self.return_data(False,'',error_msg='The specified version is not compatible with your server operating system')

        # 下载文件
        url = "{}/{}/node-{}-{}".format(self._node_url,version,version,fname)
        save_file = "{}/node-{}-{}".format(self._nodejs_path,version,fname)
        self.__download_file(url,save_file)
        if not os.path.exists(save_file):
            return self.return_data(False,'',error_msg='File download failed, please try again later!')

        # 解压
        public.ExecShell("tar -zxvf {} -C {}".format(save_file,self._nodejs_path))
        if os.path.exists(save_file):os.remove(save_file)

        # 重命名和配置权限
        un_path = '{}/node-{}-{}'.format(self._nodejs_path,version,namex)
        re_path = '{}/{}'.format(self._nodejs_path,version)
        if os.path.exists(re_path):
            import shutil
            shutil.rmtree(re_path)
        os.rename(un_path,re_path)
        public.ExecShell("chown -R root:root {}".format(re_path))

        # 修改当前版本的Node-env
        node_bin = '{}/bin/node'.format(re_path)
        npm_js = '{}/lib/node_modules/npm/bin/npm-cli.js'.format(re_path)
        npx_js = '{}/lib/node_modules/npm/bin/npx-cli.js'.format(re_path)
        
        npm_body = public.readFile(npm_js)
        if npm_body:
            npm_body = npm_body.replace('#!/usr/bin/env node','#!{}'.format(node_bin))
            public.writeFile(npm_js,npm_body)
        npx_body = public.readFile(npx_js)
        if npx_body:
            npx_body = npx_body.replace('#!/usr/bin/env node','#!{}'.format(node_bin))
            public.writeFile(npx_js,npx_body)
        # get.module = 'pm2'
        # self.install_module(get)
        return self.return_data(True,'Successful installation')


    def uninstall_nodejs(self,get):
        '''
            @name 写在指定nodejs版本
            @author hwliang<2021-07-30>
            @param get<dict_obj>{
                version: string<版本号>
            }
            @return dict
        '''
        version = get['version']
        version_info = self.get_version_info(get)
        if not version_info['status']: return version_info
        version_info = version_info['data']
        if not version_info['setup']: return self.return_data(False,'',error_msg='This version does not need to be uninstalled')
        re_path = '{}/{}'.format(self._nodejs_path,version)
        if not os.path.exists(re_path): return self.return_data(False,'',error_msg='This version does not exist')
        public.ExecShell("rm -rf {}".format(re_path))
        if self.get_default_env(None) == version:
            self.set_default_env(None)
        return self.return_data(True,'Uninstalled successfully')


    def get_modules(self,get):
        '''
            @name 获取指定node版本当前已安装的模块信息
            @author hwliang<2021-07-30>
            @param args<dict_obj{
                version: string<版本号>
            }>
            @return list
        '''
        if not 'version' in get: return public.returnMsg(False,'Missing parameters!')
        mod_path = os.path.join(self._nodejs_path,get.version,'lib/node_modules')
        modules = []
        if not os.path.exists(mod_path): return modules
        for mod_name in os.listdir(mod_path):
            try:
                mod_pack_file = os.path.join(mod_path,mod_name,'package.json')
                if not os.path.exists(mod_pack_file): continue
                mod_pack_info = json.loads(public.readFile(mod_pack_file))
                pack_info = {
                    "name": mod_name, 
                    "version": mod_pack_info['version'],
                    "description":mod_pack_info['description'],
                    "license": mod_pack_info['license'] if 'license' in mod_pack_info else 'NULL',
                    "homepage": mod_pack_info['homepage'] if 'homepage' in mod_pack_info else 'NULL'
                    }
                modules.append(pack_info)
            except:
                continue
        return modules


    def module_exists(self,version,module):
        '''
            @name 检查指定node版本当前已安装的模块信息
            @author hwliang<2021-07-30>
            @param version<string> 版本号
            @param module<string> 模块名
            @return bool
        '''
        mod_path = os.path.join(self._nodejs_path,version,'lib/node_modules')
        if not os.path.exists(mod_path): return False
        for mod_name in os.listdir(mod_path):
            if mod_name == module: return True
        return False


    def upgrade_module(self,get):
        '''
            @name 升级指定node版本指定模块
            @author hwliang<2021-07-31>
            @param get<dict_obj>{
                version: string<版本号>
                module: string<模块名>
            }
            @return dict
        '''

        if not 'version' in get or not 'module' in get: return self.return_data(False,'',error_msg='Missing parameters!')
        version = get['version'].strip()
        module = get['module'].strip()
        if module == 'npm':
            if version[:2] in ['v4','v6']: return self.return_data(False,'',error_msg='It is currently the latest version, no need to upgrade!')
        npm_bin = os.path.join(self._nodejs_path,version,'bin/npm')
        mod_path = os.path.join(self._nodejs_path,version,'lib/node_modules')
        if not os.path.exists(npm_bin): return self.return_data(False,'',error_msg='The specified node version is not installed!')
        module = module.strip()
        if not self.module_exists(version,module): 
            return self.return_data(False,'',error_msg='The specified module is not installed!')
        
        mod_pack_file = os.path.join(mod_path,module,'package.json')
        old_mod_pack_info = json.loads(public.readFile(mod_pack_file))
        
        public.set_mode(npm_bin,755)
        exec_cmd = '''{}
{} update -global {} &> {}'''.format(self.get_shell_env(version),npm_bin,module,self._exec_log)
        public.ExecShell(exec_cmd)
        if not os.path.exists(mod_pack_file): 
            return self.return_data(False,'',error_msg='Upgrade failed!')
        mod_pack_info = json.loads(public.readFile(mod_pack_file))
        if old_mod_pack_info['version'] == mod_pack_info['version']: return self.return_data(False,'',error_msg='It is currently the latest version, no need to upgrade!')

        return self.return_data(True,'Successfully upgraded {} module to {}'.format(module,mod_pack_info['version']))
        

    def install_module(self,get):
        '''
            @name 安装指定node版本指定模块
            @author hwliang<2021-07-30>
            @param get<dict_obj>{
                version: string<版本号>
                module: string<模块名>
            }
            @return dict
        '''
        if not 'version' in get or not 'module' in get: return self.return_data(False,'',error_msg='Missing parameters!')
        version = get['version'].strip()
        module = get['module'].strip()
        npm_bin = os.path.join(self._nodejs_path,version,'bin/npm')
        mod_path = os.path.join(self._nodejs_path,version,'lib/node_modules')
        if not os.path.exists(npm_bin): return self.return_data(False,'',error_msg='The specified node version is not installed!')
        module = module.strip()
        if self.module_exists(version,module): 
            return self.return_data(False,'',error_msg='The specified module has been installed!')
        
        mod_pack_file = os.path.join(mod_path,module,'package.json')
        
        public.set_mode(npm_bin,755)
        exec_cmd = '''{}
{} install {} -g &> {}'''.format(self.get_shell_env(version),npm_bin,module,self._exec_log)
        public.ExecShell(exec_cmd)
#         if module in ['pm2']:
#             exec_cmd = '''{}
# {} install {} -g &> {}'''.format(self.get_shell_env(version),npm_bin,'yarn',self._exec_log)
#             public.ExecShell(exec_cmd)
        if not os.path.exists(mod_pack_file): 
            return self.return_data(False,'',error_msg='installation failed!')

        return self.return_data(True,'Successful installation')

    def uninstall_module(self,get):
        '''
            @name 卸载指定node版本指定模块
            @author hwliang<2021-07-31>
            @param get<dict_obj>{
                version: string<版本号>
                module: string<模块名>
            }
            @return dict
        '''

        if not 'version' in get or not 'module' in get: return self.return_data(False,'',error_msg='Missing parameters!')
        version = get['version'].strip()
        module = get['module'].strip()
        if module in ['npm']: 
            return self.return_data(False,'',error_msg='Prohibit uninstalling {} module!'.format(module))
        npm_bin = os.path.join(self._nodejs_path,version,'bin/npm')
        mod_path = os.path.join(self._nodejs_path,version,'lib/node_modules')
        if not os.path.exists(npm_bin): return self.return_data(False,'',error_msg='The specified node version is not installed!')
        module = module.strip()
        if not self.module_exists(version,module): 
            return self.return_data(False,'',error_msg='The specified module is not installed!')
        
        mod_pack_file = os.path.join(mod_path,module,'package.json')
        public.set_mode(npm_bin,755)
        exec_cmd = '''{}
{} uninstall {} -g &> {}'''.format(self.get_shell_env(version),npm_bin,module,self._exec_log)
        public.ExecShell(exec_cmd)
        if os.path.exists(mod_pack_file): 
            return self.return_data(False,'',error_msg='Uninstallation failed!')

        return self.return_data(True,'Successfully uninstalled')

    
    def get_default_env(self,get):
        '''
            @name 获取默认nodejs版本
            @author hwliang<2021-07-30>
            @param get<dict_obj>
            @return dict
        '''
        # 不存在默认版本
        env_node_bin = '/usr/bin/node'
        env_npm_bin = '/usr/bin/npm'
        env_npx_bin = '/usr/bin/npx'
        if not os.path.islink(env_node_bin):
            return self.return_data(False,'',error_msg='No default Node.js version is currently set!')
        
        # 读取软链接路径
        node_lnk_path = os.readlink(env_node_bin)

        # 移除无效的软链接
        if not os.path.exists(node_lnk_path): 
            if os.path.exists(env_node_bin) or os.path.islink(env_node_bin): os.remove(env_node_bin)
            if os.path.exists(env_npm_bin) or os.path.islink(env_node_bin): os.remove(env_npm_bin)
            if os.path.exists(env_npx_bin) or os.path.islink(env_node_bin): os.remove(env_npx_bin)
            return self.return_data(False,'',error_msg='No default Node.js version is currently set!')
        
        # 不是通过宝塔设置的默认软链接
        if node_lnk_path.find(self._nodejs_path) != 0:
            return self.return_data(False,'',error_msg='No default Node.js version is currently set!')

        # 从软链路径中获取版本号
        version = node_lnk_path[len(self._nodejs_path)+1:].split('/')[0]
        if not get: return version
        return self.return_data(True,version)


    def set_profile(self,nodejs_version = None,clear=False):
        '''
            @name 设置.profile
            @author hwliang<2021-07-30>
            @param nodejs_version string<版本号>
            @param clear bool<是否清除原有配置>
            @return bool
        '''
        profile = '/root/.profile'
        if not os.path.exists(profile): return False
        public.ExecShell("sed -i '/BT-NODE-ENV/d' {}".format(profile))
        if clear: return True
        pro_body = public.readFile(profile)
        if not pro_body: return False
        # if pro_body.find('# BT-NODE-ENV') == -1: return False
        pro_body = pro_body.strip()
        nodejs_bin_path = "{}/{}/bin".format(self._nodejs_path,nodejs_version)
        pro_body += "\n"
        pro_body += "PATH={}:$PATH # BT-NODE-ENV\n".format(nodejs_bin_path)
        pro_body += "export PATH # BT-NODE-ENV\n".format(nodejs_bin_path)
        public.writeFile(profile,pro_body)
        return True
        


    def set_default_env(self,get):
        '''
            @name 设置默认nodejs版本
            @author hwliang<2021-07-30>
            @param get<dict_obj>{
                version: string<版本号>
            }
            @return dict
        '''
        if 'version' in get:
            if get.version == '0': 
                self.set_nvm_env()
                get = None

        
        if get:
            # 前置检查
            if not 'version' in get: return self.return_data(False,'',error_msg='Missing parameters!')
            version = get['version'].strip()
            src_node_bin = os.path.join(self._nodejs_path,version,'bin/node')
            src_npm_bin = os.path.join(self._nodejs_path,version,'lib/node_modules/npm/bin/npm-cli.js')
            src_npx_bin = os.path.join(self._nodejs_path,version,'lib/node_modules/npm/bin/npx-cli.js')
            src_pm2_bin = os.path.join(self._nodejs_path,version,'lib/node_modules/pm2/bin/pm2')
            src_yarn_bin = os.path.join(self._nodejs_path,version,'lib/node_modules/yarn/bin/yarn.js')
            if not os.path.exists(src_node_bin):
                return self.return_data(False,'',error_msg='指定版本不存在!')
        
        # 移除当前默认软链接
        env_node_bin = '/usr/bin/node'
        env_npm_bin = '/usr/bin/npm'
        env_npx_bin = '/usr/bin/npx'
        env_pm2_bin = '/usr/bin/pm2'
        env_yarn_bin = '/usr/bin/yarn'
        if os.path.exists(env_node_bin) or os.path.islink(env_node_bin): os.remove(env_node_bin)
        if os.path.exists(env_npm_bin) or os.path.islink(env_npm_bin): os.remove(env_npm_bin)
        if os.path.exists(env_npx_bin) or os.path.islink(env_npx_bin):  os.remove(env_npx_bin)
        if os.path.exists(env_pm2_bin) or os.path.islink(env_pm2_bin):  os.remove(env_pm2_bin)
        if os.path.exists(env_yarn_bin) or os.path.islink(env_yarn_bin):  os.remove(env_yarn_bin)

        if get:
            # 设置软链接到/usr/bin
            if os.path.islink(src_node_bin):
                src_node_bin = os.readlink(src_node_bin)

            if os.path.exists(src_node_bin): os.symlink(src_node_bin,env_node_bin)
            if os.path.exists(src_npm_bin): os.symlink(src_npm_bin,env_npm_bin)
            if os.path.exists(src_npx_bin): os.symlink(src_npx_bin,env_npx_bin)
            if os.path.exists(src_pm2_bin): os.symlink(src_pm2_bin,env_pm2_bin)
            if os.path.exists(src_yarn_bin): os.symlink(src_yarn_bin,env_yarn_bin)
            
            if not os.path.exists(env_node_bin): 
                return self.return_data(False,'',error_msg='Setup failed!')
            self.clear_nvm_env()
            self.set_profile(version)
        else:
            self.set_profile(clear=True)

        

        return self.return_data(True,'Set up successfully!')
        