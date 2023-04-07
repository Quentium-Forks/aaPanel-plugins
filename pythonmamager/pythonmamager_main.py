#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: zhwen <zhw@bt.cn>
# +-------------------------------------------------------------------

# +--------------------------------------------------------------------
# |   pythone管理器
# +--------------------------------------------------------------------
import os, sys

os.chdir("/www/server/panel")
sys.path.append("class/")
import public, time, json, re, platform


class pythonmamager_main:
    basedir = "/www/server/panel/plugin/pythonmamager"
    __conf = "%s/config.json" % basedir
    logpath = "%s/logs" % basedir
    pipsource = "https://mirrors.aliyun.com/pypi/simple/"
    logs_file_tmp = "{}/py.log".format(basedir)
    access_defs = ['auto_start']

    def __init__(self):
        self.pyenv_path = "/root/.pyenv"
        if not os.path.exists(self.pyenv_path):
            self.pyenv_path = "/.pyenv"

    def write_log_tmp(self,log_str):
        if not log_str:
            f = open(self.logs_file_tmp, 'wb')
            log_str = "{}\n".format("-"*60)
        else:
            f = open(self.logs_file_tmp, 'ab+')
            log_str += "\n"
        f.write(log_str.encode('utf-8'))
        f.close()
        return True

    # 检查端口
    def __check_port(self, port):
        try:
            if int(port) < 65535 and int(port) > 0:
                data = public.ExecShell("ss  -nultp|grep ':%s '" % port)[0]
                if data:
                    return public.returnMsg(False, "The port is already occupied")
            else:
                return public.returnMsg(False, "Please enter the correct port range 1 < port < 65535")
        except:
            return public.returnMsg(False, "Please enter an integer for the port")

    # 检查输入参数
    def __check_args(self,get):
        values = {}
        # frameworks = ["python", "django", "flask", "sanic"]
        if hasattr(get,"pjname"):
            pjname = get.pjname.strip()
            if sys.version_info.major < 3:
                if len(pjname) < 3 or len(pjname) > 15:
                    return public.returnMsg(False, 'The name must be greater than 3 and less than 15 strings')
            else:
                if len(pjname.encode("utf-8")) < 3 or len(pjname.encode("utf-8")) > 15:
                    return public.returnMsg(False, 'The name must be greater than 3 and less than 15 strings')
            values["pjname"] = pjname
        if hasattr(get,"port"):
            port = get.port.strip()
            if port != "":
                result = self.__check_port(port)
                if result:
                    return result
            values["port"] = port
        if hasattr(get,"path"):
            values["path"] = get.path.strip()
        if hasattr(get,"version"):
            values["version"] = get.version.strip()
        if hasattr(get,"install_module"):
            values["install_module"] = get.install_module.strip()
        if hasattr(get,"framework"):
            danger_args = ["rm -f", "rm -rf"]
            for i in danger_args:
                if i in get.framework:
                    return public.returnMsg(False, 'The command line contains dangerous commands. .')
            values["framework"] = get.framework
            # if values["framework"] not in frameworks:
            #     get.rfile = ""
        if hasattr(get,"rtype"):
            values["rtype"] = get.rtype.strip()
        if hasattr(get,"rfile"):
            values["rfile"] = get.rfile.strip()
        if hasattr(get,"auto_start"):
            values["auto_start"] = get.auto_start.strip()
        if hasattr(get,"user"):
            if get.user in ['root','www']:
                values["user"] = get.user.strip()
        if hasattr(get,"parm"):
            values["parm"] = get.parm.strip()
        else:
            values["parm"] = ''
        return values

    # 检查项目是否存在
    def __check_project_exist(self,pjname):
        conf = self.__read_config(self.__conf)
        for i in conf:
            if pjname == i["pjname"]:
                return public.returnMsg(False, "Project already exists")

    def get_vpath_pip(self,vpath):
        if os.path.exists('{}/bin/pip'.format(vpath)):
            return '{}/bin/pip'.format(vpath)
        else:
            return '{}/bin/pip3'.format(vpath)

    def get_vpath_python(self,vpath):
        if os.path.exists('{}/bin/python'.format(vpath)):
            return '{}/bin/python'.format(vpath)
        else:
            return '{}/bin/python3'.format(vpath)

    # 安装模块
    def __install_module(self,install_module,path,vpath):
        requirementsconf={}
        requirements = "%s/requirements.txt" % path
        if install_module == "1":
            self.write_log_tmp("|-开始安装模块：{}".format(requirements))
            if not os.path.exists(requirements):
                self.write_log_tmp("|-文件不存在：{}".format(requirements))
                return public.returnMsg(False, "The dependent file [requirements.txt] is not found in the root path, please add it before creating")
            requirementsconf = public.readFile(requirements).splitlines()
            for i in requirementsconf:
                shell = "{} install -i {} {}".format(self.get_vpath_pip(vpath), self.pipsource, i)
                self.write_log_tmp("|-开始安装模块：{}".format(i))
                self.write_log_tmp("|-安装命令：{}".format(shell))
                a = public.ExecShell(shell)
                self.WriteLog(a[0])
            return requirementsconf
        else:
            self.write_log_tmp("|-跳过模块安装...")
            return requirementsconf

    # 读取requirements内容
    def __read_requirements(self,path):
        requirements = "%s/requirements.txt" % path
        if os.path.exists(requirements):
            requirements_data = public.readFile(requirements)
            return requirements_data

    # 构造启动参数
    def __structure_start_args(self,values):
        rfile = values['rfile']
        framework = values['framework']
        rproject = rfile.split("/")[-1].split(".")[0]
        if rproject == "":
            rproject = rfile.split("/")[-2].split(".")[0]
        run = "%s:app" % rproject
        if framework == "django":
            run = "%s.wsgi:application" % rproject
        if framework == "sanic":
            worker = "worker_class = 'sanic.worker.GunicornWorker'"
        else:
            worker = "worker_class = 'geventwebsocket.gunicorn.workers.GeventWebSocketWorker'"
        return {"run":run,"worker":worker,"framework":framework,"rproject":rproject}

    # 自定义启动
    def __start_with_customize(self,values):
        run_user = ""
        if values['user'] == 'www':
            run_user = "sudo -u {}".format(values['user'])
        sh = " nohup {} {} {} 2>&1 &".format(run_user,self.get_vpath_python(values['vpath']),values['rfile'],"{}/logs/error.log".format(values['path']))
        self._create_sh(values['pjname'],sh)
        public.ExecShell('systemctl restart {}_pymanager'.format(['pjname']))

    # 使用python启动
    def __start_with_python(self,values):
        logpath = "%s/logs/" % values['path']
        if not os.path.exists(logpath):
            public.ExecShell("mkdir %s" % logpath)
        run_user = ""
        if values['user'] == 'www':
            run_user = "sudo -u {}".format(values['user'])
        sh = "cd {path} && nohup {user} {vpath} -u {run_file} {parm} >> {log} 2>&1 &".format(
            path=values['path'],
            vpath=self.get_vpath_python(values['vpath']),
            run_file=values['rfile'],
            log=logpath + "error.log",
            user=run_user,
            parm=values['parm']
        )
        self.WriteLog(sh)
        self._create_sh(values['pjname'],sh)
        public.ExecShell('systemctl restart {}_pymanager'.format(values['pjname']))
        time.sleep(1)

    # 使用uwsgi启动
    def __start_with_wsgi(self,values):
        path = values['path']
        vpath = values['vpath']
        pjname = values['pjname']
        user = values['user']
        port = values['port']
        rfile = values['rfile']
        run = values['run']
        framework = values['framework']
        if path[-1] == "/":
            path = path[:-1]
        if framework == "sanic":
            return public.returnMsg(False, "Sanic framework project please use gunicorn or pyhton to start")
        self.write_log_tmp("|-开始安装uwsgi模块...")
        a = public.ExecShell("{} install -i {} uwsgi >> {}".format(
            self.get_vpath_pip(vpath), self.pipsource,self.logs_file_tmp))
        self.WriteLog(a[0])
        # 添加uwcgi配置
        uconf = """[uwsgi]
master = true
processes = 1
threads = 2
chdir = {path}
wsgi-file= {rfile}
http = 0.0.0.0:{port}
logto = {path}/logs/error.log
chmod-socket = 660
vacuum = true
master = true
uid={user}
gid={user}
max-requests = 1000""" .format(path=path, port=port, rfile=rfile, user=user)
        uwsgi_file = "%s/uwsgi.ini" % path
        if not os.path.exists(uwsgi_file):
            public.writeFile(uwsgi_file, uconf)
        public.ExecShell("mkdir %s/logs" % path)
        sh = "nohup %s/bin/uwsgi --ini %s/uwsgi.ini -w %s > /dev/null 2>&1 &" % (vpath, path, run)
        self._create_sh(pjname,sh)
        public.ExecShell('systemctl restart {}_pymanager'.format(pjname))
        time.sleep(1)

    # 使用gunicorn启动
    def __start_with_gunicorn(self,values):
        path = values['path']
        vpath = values['vpath']
        pjname = values['pjname']
        user = values['user']
        worker = values['worker']
        port = values['port']
        run = values['run']
        a = public.ExecShell("{} install -i {} gunicorn gevent-websocket >> {}".format(
                self.get_vpath_pip(vpath), self.pipsource,self.logs_file_tmp))
        self.WriteLog(a[0])
        # 添加gunicorn配置
        logformat = '%(t)s %(p)s %(h)s "%(r)s" %(s)s %(L)s %(b)s %(f)s" "%(a)s"'
        gconf = """bind = '0.0.0.0:{port}'
user = '{user}'
workers = 1
threads = 2
backlog = 512
daemon = True
chdir = '{chdir}'
access_log_format = '{log}'
loglevel = 'info'
{worker}
errorlog = chdir + '/logs/error.log'
accesslog = chdir + '/logs/access.log'
pidfile = chdir + '/logs/{pjname}.pid'""".format(
            port=port, chdir=path, log=logformat, worker=worker, pjname=pjname,user=user)
        gunicorn_file = "%s/gunicorn.conf" % path
        if not os.path.exists(gunicorn_file):
            public.writeFile(gunicorn_file, gconf)
        public.ExecShell("mkdir %s/logs" % path)
        sh = "%s/bin/gunicorn -c %s/gunicorn.conf %s" % (vpath, path, run)
        self._create_sh(pjname,sh)
        public.ExecShell('systemctl restart {}_pymanager'.format(pjname))
        time.sleep(1)
        pid = public.ExecShell("ps aux|grep '%s'|grep -v 'grep'|wc -l" % vpath)[0].strip("\n")

        if pid == "0":
            public.ExecShell('/etc/init.d/{}_pymanager'.format(pjname))

    # 选择启动方式
    def __select_framework(self,values):
        self.write_log_tmp("|-开始选择启动框架...")
        rtype = values['rtype']
        rtypes = ["python","gunicorn","uwsgi"]
        if rtype not in rtypes:
            self.write_log_tmp("|-项目启动方式：{}".format("自定义"))
            self.__start_with_customize(values)
            return
        start_args = self.__structure_start_args(values)
        values['run'] = start_args["run"]
        values['worker'] = start_args["worker"]
        # framework = start_args["framework"]
        # rproject = start_args["rproject"]
        if rtype == "python":
            self.write_log_tmp("|-项目启动方式：{}".format("python"))
            self.__start_with_python(values)

        if rtype == "uwsgi":
            self.write_log_tmp("|-项目启动方式：{}".format("uwsgi"))
            self.__start_with_wsgi(values)

        if rtype == "gunicorn":
            self.write_log_tmp("|-项目启动方式：{}".format("gunicorn"))
            self.__start_with_gunicorn(values)

    # 检查项目状态并写入配置
    def __check_project_status(self,data,path):
        pid = public.ExecShell("ps aux|grep '%s'|grep -v 'grep'|wc -l" % path)[0].strip("\n")
        conf = self.__read_config(self.__conf)
        if pid != "0":
            data["status"] = "1"
            conf.append(data)
            self.__write_config(self.__conf, conf)
            return public.returnMsg(True, "Created successfully")
        else:
            data["status"] = "0"
            conf.append(data)
            self.__write_config(self.__conf, conf)
            return public.returnMsg(False, "Created failed")

    # 创建python项目
    def CreateProject(self, get):
        # self.set_auto_start()
        values = self.__check_args(get)
        if "status" in values:
            return values
        result = self.__check_project_exist(values["pjname"])
        if result:
            return result
        vpath = values["path"] + "/" + public.md5(values["pjname"]) + "_venv"
        get.vpath = vpath
        if not os.path.exists(vpath):
            self.write_log_tmp("|-No virtual environment, create now [{}]".format(vpath))
            self.copy_pyv(get)
        requirements = self.__install_module(values["install_module"],values["path"],vpath)
        if "status" in requirements:
            return requirements
        data = {
            "pjname": values["pjname"],
            "version": values["version"],
            "rfile": values["rfile"],
            "path": values["path"],
            "vpath": vpath,
            "status": "0",
            "port": values["port"],
            "rtype": values["rtype"],
            "proxy": "",
            "framework": values["framework"],
            "auto_start": values['auto_start'],
            "user": values["user"],
            "parm":values["parm"]
        }
        # public.ExecShell("chown -R www.www {}".format(values["path"]))
        self.__select_framework(data)
        if values["install_module"] == "0":
            conf = self.__read_config(self.__conf)
            conf.append(data)
            self.__write_config(self.__conf, conf)
            self._set_sys_auto_start(values["pjname"],values['auto_start'])
            return public.returnMsg(True, "Created successfully")
        return self.__check_project_status(data,values["path"])

    # 获取项目详细信息
    def GetLoad(self, pjname):
        conf = self.__read_config(self.__conf)
        cpunum = int(public.ExecShell('cat /proc/cpuinfo |grep "processor"|wc -l')[0])
        for i in conf:
            if i["pjname"] == pjname:
                try:
                    cpu = round(float(
                        public.ExecShell("ps aux|grep '%s'|awk '{cpusum += $3};END {print cpusum}'" % i["path"])[
                            0]) / cpunum, 2)
                    mem = round(float(public.ExecShell(
                        "ps aux|grep '%s'|grep -v 'grep'|awk '{memsum+=$6};END {print memsum}'" % i["path"])[0]) / 1024,2)
                    return {"cpu": cpu, "mem": mem}
                except:
                    return {"cpu": 0, "mem": 0}

    # 获取已经安装的模块
    def GetPackages(self, get):
        conf = self.__read_config(self.__conf)
        piplist = {}
        for i in conf:
            if i["pjname"] == get.pjname:
                l = public.ExecShell("%s list" % self.get_vpath_pip(i["vpath"]))[0].split("\n")
                for d in l[2:]:
                    try:
                        p, v = d.split()
                        piplist[p] = v
                    except:
                        pass
                return piplist

    # 取文件配置
    def GetConfFile(self, get):
        conf = self.__read_config(self.__conf)
        pjname = get.pjname.strip()
        import files
        for i in conf:
            if pjname == i["pjname"]:
                if i["rtype"] == "python":
                    return public.returnMsg(False, "Python startup mode has no configuration file to modify")
                elif i["rtype"] == "gunicorn":
                    get.path = i["path"] + "/gunicorn.conf"
                else:
                    get.path = i["path"] + "/uwsgi.ini"
                f = files.files()
                return f.GetFileBody(get)

    def __get_conf_port(self,config,py_conf):
        rep_socket = "socket\s*="
        socket = re.search(rep_socket,config)
        if socket:
            py_conf["port"] = ""
        rep_port = ".+:(\d+)"
        try:
            new_port = re.search(rep_port,config).group(1)
            result = self.__check_port(new_port)
            if not result:
                py_conf["port"] = new_port
            else:
                return result
        except Exception as e:
            return e

    # 保存文件配置
    def SaveConfFile(self, get):
        conf = self.__read_config(self.__conf)
        import files
        pjname = get.pjname.strip()
        for i in conf:
            if pjname == i["pjname"]:
                result = self.__get_conf_port(get.data,i)
                if result:
                    return result
                if i["rtype"] == "python":
                    return public.returnMsg(False, "Python startup mode has no configuration file to modify")
                elif i["rtype"] == "gunicorn":
                    get.path = i["path"] + "/gunicorn.conf"
                else:
                    get.path = i["path"] + "/uwsgi.ini"
                f = files.files()
                result = f.SaveFileBody(get)
                if result["status"]:
                    public.writeFile(self.__conf,json.dumps(conf))
                    return public.returnMsg(True, "The configuration is successfully modified. Please restart the project manually.")
                else:
                    return public.returnMsg(False, "Save failed")

    # 安装卸载虚拟环境模块
    def MamgerPackage(self, get):
        conf = self.__read_config(self.__conf)
        for i in conf:
            if i["pjname"] == get.pjname:
                shell = "%s install -i %s %s"
                if get.act == "install":
                    if get.v:
                        v = "%s==%s" % (get.p, get.v)
                        public.ExecShell(shell % (self.get_vpath_pip(i["vpath"]), self.pipsource, v))
                    else:
                        public.ExecShell(shell % (self.get_vpath_pip(i["vpath"]), self.pipsource, get.p))
                    packages = public.ExecShell("%s list" % self.get_vpath_pip(i["vpath"]))[0]
                    if get.p in packages.lower():
                        return public.returnMsg(True, "Successful installation")
                    else:
                        return public.returnMsg(False, "installation failed")
                else:
                    if get.p == "pip":
                        return public.returnMsg(False, "PIP cannot be uninstalled...")
                    shell = "echo 'y' | %s uninstall %s"
                    public.ExecShell(shell % (self.get_vpath_pip(i["vpath"]), get.p))
                    packages = public.ExecShell("%s list" % self.get_vpath_pip(i["vpath"]))[0]
                    if get.p not in packages.lower():
                        return public.returnMsg(True, "Uninstall successfully")
                    else:
                        return public.returnMsg(False, "Uninstall failed")

    # 获取项目列表
    def GetPorjectList(self, get):
        conf = self.__read_config(self.__conf)
        if conf:
            # 取项目状态
            for i in conf:
                a = public.ExecShell("ps aux|grep '%s'|grep -v 'grep'|wc -l" % i["path"])[0].strip("\n")
                if a == "0":
                    i["status"] = "0"
                    i["cpu"] = 0
                    i["mem"] = 0
                else:
                    i["status"] = "1"
                    load = self.GetLoad(i["pjname"])
                    i["cpu"] = load["cpu"]
                    i["mem"] = load["mem"]
            self.__write_config(self.__conf, conf)
            return conf
        else:
            return public.returnMsg(True, "Get success")

    # 获取framework兼容老版本
    def __get_framework(self,path):
        requirements = "%s/requirements.txt" % path
        if "django" in requirements:
            framework = "django"
        elif "flask" in requirements:
            framework = "flask"
        elif "sanic" in requirements:
            framework = "sanic"
        else:
            framework = "python"
        return framework
    # 启动项目
    def StartProject(self, get):
        conf = self.__read_config(self.__conf)
        if hasattr(get,"pjname"):
            pjname = get.pjname
        else:
            pjname = get
        if conf:
            if not os.path.exists(self.logpath):
                public.ExecShell("mkdir -p %s" % self.logpath)
            for i in conf:
                if pjname == i["pjname"]:
                    if i["status"] == "0":
                        if "framework" not in i:
                            i["framework"] = self.__get_framework(i["path"])
                            self.__write_config(self.__conf, conf)
                        self.__select_framework(i)
                        pid = public.ExecShell("ps aux|grep '%s'|grep -v 'grep'|wc -l" % i["vpath"])[0].strip("\n")

                        if pid != "0":
                            print("Startup successful")
                            return public.returnMsg(True, "Startup successful")
                        else:
                            print("Project startup failed, please check the project log")
                            return public.returnMsg(False, "Project startup failed, please check the project log")
                    else:
                        print("The project has started")
                        return public.returnMsg(False, "The project has started")

    # 命令启动
    def auto_start(self):
        conf = self.__read_config(self.__conf)
        for i in conf:
            if i["auto_start"] == "1":
                argv = i["pjname"]
                self.StartProject(argv)

    # 编辑开机启动
    def edit_auto_start(self,get):
        self.set_auto_start()
        vaules = self.__check_args(get)
        conf = self.__read_config(self.__conf)
        for i in conf:
            if vaules["pjname"] == i["pjname"]:
                i["auto_start"] = vaules["auto_start"]
                self.__write_config(self.__conf,conf)
                if vaules["auto_start"] == "1":
                    public.ExecShell('systemctl enable {}_pymanager'.format(vaules["pjname"]))
                else:
                    public.ExecShell('systemctl disable {}_pymanager'.format(vaules["pjname"]))
                return public.returnMsg(True, "Setup Successful")

    def set_auto_start(self):
        rc_local = public.readFile("/etc/rc.local")
        public.ExecShell('chmod +x /etc/rc.d/rc.local')
        if not re.search("pythonmamager_main\.py",rc_local):
            body = "/usr/bin/python /www/server/panel/plugin/pythonmamager/pythonmamager_main.py"
            public.writeFile("/etc/rc.local",body,"a+")

    def _set_sys_auto_start(self,pjname,auto_start):
        if auto_start == "1":
            public.ExecShell('systemctl enable {}_pymanager'.format(pjname))

    def _del_sh(self,name):
        filename = "/etc/init.d/{}_pymanager".format(name)
        if os.path.exists(filename):
            os.remove(filename)
        filename = "/lib/systemd/system/{}_pymanager".format(name)
        if os.path.exists(filename):
            public.ExecShell('systemctl disable {}_pymanager'.format(name))
            os.remove(filename)
            public.ExecShell('systemctl daemon-reload')

    def _create_sh(self,name,sh):
        string = """#!/bin/bash
# chkconfig: 2345 55 25
# description: {0}

### BEGIN INIT INFO
# Provides:          {0}
# Required-Start:    $all
# Required-Stop:     $all
# Default-Start:     2 3 4 5
# Default-Stop:      0 1 6
# Short-Description: {0}
# Description:       {0}
### END INIT INFO
{1}
""".format(name,sh)
        filename = "/etc/init.d/{}_pymanager".format(name)
        public.writeFile(filename,string)
        os.chmod(filename,755)

        service_string = """[Unit]Description=-------{}---------

[Service]
Type=forking
ExecStart=/bin/sh -c '{}'

ExecReload=/bin/sh -c '/bin/kill -HUP $MAINPID'

ExecStop=/bin/sh -c '/bin/kill -TERM $MAINPID'

Restart=on-failure

[Install]
WantedBy=multi-user.target
""".format(name,filename)
        self.WriteLog(service_string)
        service_file = "/lib/systemd/system/{}_pymanager".format(name)
        public.writeFile(service_file,service_string)
        public.ExecShell('systemctl daemon-reload')


    # 停止项目
    def StopProject(self, get):
        conf = self.__read_config(self.__conf)
        pjname = get.pjname
        if conf:
            for i in conf:
                if pjname == i["pjname"]:
                    if i["status"] == "1":
                        pid = public.ExecShell(
                            "ps aux|grep '%s'|awk '{print $2}'" % i["path"])[0].split(
                            "\n")
                        for p in pid:
                            public.ExecShell("sync && kill -9 %s" % p)
                        i["status"] = "0"
                    else:
                        return public.returnMsg(False, "The project has stopped")
                    self.__write_config(self.__conf, conf)
                    pid = public.ExecShell("ps aux|grep '%s'|grep -v 'grep'|wc -l" % i["vpath"])[0].strip("\n")
                    if pid == "0":
                        return public.returnMsg(True, "Stop successful")
                    else:
                        return public.returnMsg(False, "Stop failure")

    # 站点映射
    def ProxyProject(self, get):
        conf = self.__read_config(self.__conf)
        pjname = get.pjname.strip()
        domain = get.domain.strip()
        n = 0
        j = 0
        for i in conf:
            if i["pjname"] == pjname:
                port = i["port"]
                j += n
                n += 1
                if not port:
                    return public.returnMsg(False, "The project has no ports that cannot be mapped. The uwsgi mode does not support sock file mode mapping at this stage.")
            else:
                n += 1

        sql = public.M('sites')
        if sql.where("name=?", (domain,)).count(): return public.returnMsg(False, 'SITE_ADD_ERR_EXISTS');
        ret = {"domain": domain, "domainlist": [], "count": 0}
        get.webname = json.dumps(ret)
        get.port = "80"
        get.ftp = 'false'
        get.sql = 'false'
        get.version = '00'
        get.ps = 'Mapping site for Python project [' + pjname + ']'
        get.path = public.M('config').where("id=?", ('1',)).getField('sites_path') + '/' + domain
        result = self.create_site(get)
        if 'status' in result: return result
        import panelSite
        s = panelSite.panelSite()
        get.sitename = domain
        x=pjname if len(pjname)<13 else pjname[:10] + "..."
        get.proxyname = "to%s" % x
        get.proxysite = 'http://127.0.0.1:%s' % port
        get.todomain = "$host"
        get.proxydir = '/'
        get.type = 1
        get.cache = 0
        get.cachetime = 1
        get.advanced = 0
        get.subfilter = "[{\"sub1\":\"\",\"sub2\":\"\"},{\"sub1\":\"\",\"sub2\":\"\"},{\"sub1\":\"\",\"sub2\":\"\"}]"
        result = s.CreateProxy(get)
        if result['status']:
            conf[j]["proxy"] = domain
            self.__write_config(self.__conf, conf)
            return public.returnMsg(True, 'Add successfully!')
        else:
            return public.returnMsg(False, 'Add failed!')

    def create_site(self, get):
        import panelSite
        s = panelSite.panelSite()
        result = s.AddSite(get)
        if 'status' in result: return result;
        result['id'] = public.M('sites').where('name=?', (get.domain,)).getField('id')
        self.set_ssl_check(get.domain)
        return result

    # 设置SSL验证目录过滤
    def set_ssl_check(self, siteName):
        rewriteConf = '''#One-click application for SSL certificate verification directory related settings
    location ~ \.well-known{
        allow all;
    }'''
        public.writeFile('vhost/rewrite/' + siteName + '.conf', rewriteConf)

    # 删除映射
    def RemoveProxy(self, get):
        conf = self.__read_config(self.__conf)
        pjname = get.pjname.strip()
        import panelSite
        for i in conf:
            if pjname == i["pjname"]:
                get.id = public.M('sites').where('name=?', (i["proxy"],)).getField("id")
                get.webname = i["proxy"]
                get.path = 1
                get.domain = i["proxy"]
                panelSite.panelSite().DeleteSite(get)
                i["proxy"] = ""
                self.__write_config(self.__conf, conf)
                return public.returnMsg(True, 'Cancel successfully!')

    # 删除项目
    def RemoveProject(self, get):
        conf = self.__read_config(self.__conf)
        pjname = get.pjname
        if conf:
            for i in range(len(conf)):
                if pjname == conf[i]["pjname"]:
                    logfile = self.logpath + "/%s.log" % pjname
                    if conf[i]["status"] == "1":
                        return public.returnMsg(False, "Please stop the project and then delete it.")
                    public.ExecShell("rm -rf %s" % conf[i]["vpath"])
                    public.ExecShell("rm -f %s" % logfile)
                    public.ExecShell("rm -f %s/uwsgi.ini" % conf[i]["path"])
                    public.ExecShell("rm -f %s/gunicorn.conf" % conf[i]["path"])
                    public.ExecShell('systemctl disable {}_pymanager'.format(pjname))
                    public.ExecShell('rm -f /etc/init.d/{}_pymanager'.format(pjname))
                    public.ExecShell('rm -f /lib/systemd/system/{}_pymanager'.format(pjname))
                    del (conf[i])
                    self.__write_config(self.__conf, conf)
                    return public.returnMsg(True, "Deleted successfully")

    # python安装
    def InstallPythonV(self, get):
        return self.new_python_install(get)

    # python卸载
    def RemovePythonV(self, get):
        conf = self.__read_config(self.__conf)
        # sysv = platform.python_version()
        v = get.version
        v = v.split()[0]
        for i in conf:
            if i["version"] == v:
                return public.returnMsg(False, "This version has a project in use, please delete the project before uninstalling")
        exist_pv = self.GetPythonV(get)
        if v not in exist_pv:
            return public.returnMsg(False, "The Python version is not installed")
        self.remove_python(v)
        exist_pv = self.GetPythonV(get)
        if v in exist_pv:
            return public.returnMsg(False, "Uninstalling Python failed, please try again")
        return public.returnMsg(True, "Uninstalling Python successfully")

    def remove_python(self,pyv):
        py = '/www/server/python_manager/versions/{}'.format(pyv)
        if os.path.exists(py):
            import shutil
            shutil.rmtree(py)

    # 显示可以安装的python版本
    def GetCloudPython(self, get):
        data = self.get_cloud_version()
        v = []
        l = {}
        for i in data:
            i = i.strip()
            if re.match("[\d\.]+", i):
                v.append(i)
        existpy = self.GetPythonV(get)
        for i in v:
            if i.split()[0] in existpy:
                l[i] = "1"
            else:
                l[i] = "0"

        l = sorted(l.items(), key=lambda d: d[0], reverse=True)
        return l

    # 获取项目日志
    def GetProjectLog(self, get):
        pjname = get.pjname
        conf = self.__read_config(self.__conf)
        for i in conf:
            if i["pjname"] == pjname:
                logpath = "%s/logs/error.log" % (i["path"])
                if os.path.exists(logpath):
                    result = public.ExecShell("tail -n 300 %s" % logpath)[0]
                    return result
                else:
                    return "The project has no logs"

    # 写日志
    def WriteLog(self, msg):
        path = "%s/py.log" % self.basedir
        localtime = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        if not os.path.exists(path):
            public.ExecShell("touch %s" % path)
        public.writeFile(path, localtime + "\n" + msg + "\n", "a+")

    # 读配置
    def __read_config(self, path):
        if not os.path.exists(path):
            public.writeFile(path, '[]')
        upBody = public.readFile(path)
        if not upBody: upBody = '[]'
        return json.loads(upBody)

    # 写配置
    def __write_config(self, path, data):
        return public.writeFile(path, json.dumps(data))

    # 获取云端python版本
    def get_cloud_version(self,get=None):
        import requests
        result = requests.get('https://endoflife.date/api/python.json')
        parsed_result = result.json()
        text = [x['latest'] for x in parsed_result]
        public.writeFile('{}/pyv.txt'.format(self.basedir),json.dumps(text))
        return text

    # 获取那些版本的python能安装
    @property
    def get_pyv_can_install(self):
        pyv = public.readFile('{}/pyv.txt'.format(self.basedir))
        if not pyv:
            return self.get_cloud_version()
        try:
            return json.loads(pyv)
        except:
            return self.get_cloud_version()

    # 获取已经安装的python版本
    def GetPythonV(self,get):
        path = '/www/server/python_manager/versions'
        if not os.path.exists(path):
            return []
        data = os.listdir(path)
        return data

    # 首次安装python
    def new_python_install(self,get):
        """
        get.version  2.7.18
        :param get:
        :return:
        """
        can_install = self.get_pyv_can_install
        if get.version not in can_install:
            return public.returnMsg(False,'This version is not yet supported, please go to the forum for feedback.')
        public.ExecShell('bash {plugin_path}/install_python.sh {pyv} &> {log}'.format(plugin_path=self.basedir,pyv=get.version,log="%s/py.log" % self.basedir))
        path = '/www/server/python_manager/versions/{}/bin/'.format(get.version)
        if "2.7" in get.version:
            path = path+"python"
        else:
            path = path + "python3"
        if os.path.exists(path):
            public.writeFile("%s/py.log" % self.basedir,'')
            return public.returnMsg(True,"Successful installation!")
        return public.returnMsg(False,"installation failed! path:{}".format(path))

    def install_pip(self,vpath,pyv):
        if [int(i) for i in pyv.split('.')] > [3,6]:
            pyv = "3.6"
        public.ExecShell('bash {plugin_path}/install_python.sh {pyv} {vpath} &>> {log}'.format(
            plugin_path=self.basedir,
            pyv=pyv,
            log="%s/py.log" % self.basedir,
            vpath = vpath))

    # 复制python环境到项目内
    def copy_pyv(self,get):
        import files
        get.sfile = "/www/server/python_manager/versions/{}".format(get.version)
        get.dfile = get.vpath
        self.WriteLog(str(files.files().CopyFile(get)))
        import pwd
        try:
            res = pwd.getpwnam('www')
        except:
            public.ExecShell("groupadd www && useradd -s /sbin/nologin -g www www")
            res = pwd.getpwnam('www')
        uid = res.pw_uid
        gid = res.pw_gid
        os.chown(get.dfile,uid,gid)
        self.install_pip(get.vpath,get.version)

    def find_file(self,path,file,l):
        if os.path.isfile(path):
            if file in path:
                l.append(path)
        else:
            for i in os.listdir(path):
                self.find_file(os.path.join(path,i),file,l)
        return l

    # 获取django项目的启动目录
    def get_django_wsgi_path(self,get):
        l=[]
        res = self.find_file(get.path,"wsgi.py",l)
        if not res:
            return False
        return "/".join(res[0].split('/')[:-1])

    # 获取manager文件路径
    def get_manager_path(self,get):
        l=[]
        res = self.find_file(get.path,"manage.py",l)
        if not res:
            return False
        return "/".join(res[0].split('/')[:-1]) + "/manage.py"

    # 获取日志
    def get_logs(self,get):
        import files
        return files.files().GetLastLine("%s/py.log" % self.basedir, 20)

if __name__ == '__main__':
    p = pythonmamager_main()
    p.auto_start()
