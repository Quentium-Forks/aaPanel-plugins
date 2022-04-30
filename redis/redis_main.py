#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: zhwen <zhw@bt.cn>
# +-------------------------------------------------------------------

#+--------------------------------------------------------------------
#|   宝塔redis管理器
#+--------------------------------------------------------------------
import sys,os,json,re

os.chdir("/www/server/panel")

sys.path.append("class/")
import public

class redis_main:
    __redis_conf_file = "/www/server/redis/redis.conf"

    # 检查redis是否已经设置密码
    def check_redis_passwd(self,conf):
        if not conf:
            return 0
        rep = "\nrequirepass\s+.*"
        if not re.search(rep,conf):
            return 2

    # 检查是否公网ip
    def check_public_ip(self,get):
        local_ip_rep = "^(127\.0\.0\.1)|(localhost)|(10\.\d{1,3}\.\d{1,3}\.\d{1,3})|(172\.((1[6-9])|(2\d)|(3[01]))\.\d{1,3}\.\d{1,3})|(192\.168\.\d{1,3}\.\d{1,3})$"
        if re.search(local_ip_rep,get.bind):
            return False
        return True

    # 检查redis是否需要强制设置密码
    def check_set_public_ip(self,get):
        if self.check_public_ip(get):
            return True

    #设置redis常用配置配置
    def SetRedisConf(self,get):
        redis_conf = public.readFile(self.__redis_conf_file)
        if self.check_set_public_ip(get):
            if not get.requirepass:
                return public.returnMsg(False, 'You must set a password before you can open public network access.')
            check_pw = self.check_redis_passwd(redis_conf)
            if check_pw == 2 and not get.requirepass:
                return public.returnMsg(False, 'You must set a password before you can open public network access.')
            if check_pw == 0:
                return public.returnMsg(False, 'Did not find the redis configuration file')
        conflist = []
        getdict = get.__dict__
        for i in getdict.keys():
            if i != "__module__" and i != "__doc__" and i != "data" and i != "args" and i != "action" and i != "s" and i != "name":
                getpost = {
                    "name": i,
                    "value": str(getdict[i])
                }
                conflist.append(getpost)
        for c in conflist:
            if c["name"] == "requirepass":
                prep = "[\~\`\/\=]"
                if re.search(prep, c["value"]):
                    return public.returnMsg(False, 'REDIS_PASSWD_ERR')
            if c["name"] == "bind":
                iprep = "(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})\.(2(5[0-5]{1}|[0-4]\d{1})|[0-1]?\d{1,2})"
                if not re.search(iprep,c["value"]):
                    return public.returnMsg(False, 'IP_FORMAT_ERR')
            if c["name"] == "port":
                try:
                    if int(c["value"]) >= 65535 or int(c["value"]) < 1:
                        return public.returnMsg(False, 'PORT_FORMAT_ERR')
                except:
                    return public.returnMsg(False, 'PORT_FORMAT_ERR')

            keys = ["timeout", "databases", "maxclients", "maxmemory"]

            for k in keys:
                if c["name"] == k:
                    if k == "maxmemory":
                        try:
                            v = int(c["value"])
                            public.writeFile("/tmp/redis.log", str(v))
                            if v == 0:
                                c["value"] = ""
                            else:
                                c["value"] = v * 1024 * 1024

                        except:
                            return public.returnMsg(False, 'MAX_MEM_ERR')
                    else:
                        try:
                            c["value"] = int(c["value"])
                        except:
                            return public.returnMsg(False, public.GetMsg('SET_FORMAT_ERR', (k,)))
            rep = "\n%s\s+(.*)" % c["name"]
            data = re.search(rep,redis_conf)
            if data:
                if c["value"] == "":
                    redis_conf = re.sub(rep, "", redis_conf)
                new_conf = "\n%s %s" % (c["name"], c["value"])
                redis_conf = re.sub(rep, new_conf, redis_conf)
            else:
                if c["value"] != "":
                    rep = "# Redis configuration file example.\n"
                    new_conf = "%s %s\n" % (c["name"], c["value"])
                    redis_conf = re.sub(rep, "%s%s" % (rep,new_conf), redis_conf)
        public.writeFile(self.__redis_conf_file,redis_conf)
        return public.returnMsg(True, 'SET_SUCCESS')

    # 读取常用配置
    def GetRedisConf(self,get):
        try:
            redis_conf = public.readFile(self.__redis_conf_file)
            result = []
            n=0
            ps = [public.GetMsg("REDIS_CONF_TIPS1"),public.GetMsg("REDIS_CONF_TIPS2"),public.GetMsg("REDIS_CONF_TIPS3"),public.GetMsg("REDIS_CONF_TIPS4"),public.GetMsg("REDIS_CONF_TIPS5"),public.GetMsg("REDIS_CONF_TIPS6"),public.GetMsg("REDIS_CONF_TIPS7")]
            keys = ["bind","port","timeout","maxclients","databases","requirepass","maxmemory"]
            for k in keys:
                rep = "\n%s\s+(.+)" % k
                group = re.search(rep,redis_conf)
                v = ""
                if not group:
                    if k == "maxmemory":
                        v = "0"
                    if k == "maxclients":
                        v = "10000"
                    if k == "requirepass":
                        v = ""
                else:
                    if k == "maxmemory":
                        v = int(group.group(1)) / 1024 / 1024
                    else:
                        v = group.group(1)
                psstr = ps[n]
                n=n+1
                kv = {"name": k, "value": v, "ps": psstr}
                result.append(kv)
            return result
        except Exception as e:
            return public.returnMsg(False,str(e))
    # 读取持久化
    def GetRedisPersistence(self,get):
        redis_conf = public.readFile(self.__redis_conf_file)
        result = {}
        #获取RDB配置
        rdb = []
        save = re.search("\nsave[\w\s\n]+", redis_conf)
        try:
            save = save.group().split("\n")
            for i in save:
                if i:
                    i = i.split()
                    d = {"time": i[1], "keys": i[2]}
                    rdb.append(d)
            result["rdb"] = rdb
        except:
            result["rdb"] = [{"keys": "0", "time": "0"}, {"keys": "0", "time": "0"}, {"keys": "0", "time": "0"}]

        rdbdir = re.search("\ndir\s+(.+)",redis_conf)
        if not rdbdir:
            rdbdir = ""
        else:
            rdbdir = rdbdir.group(1)
        if rdbdir == "./":
            rdbdir = "/www/server/panel/"
        result["dir"] = rdbdir

        #获取AOF配置
        appendonly = "\nappendonly\s+(\w+)"
        appendonly = re.search(appendonly,redis_conf)
        if not appendonly:
            return public.returnMsg(False, "No parameter [ appendonly ] in the redis configuration file")
        appendonly = appendonly.group(1)
        appendfsync = "\nappendfsync\s+(\w+)"
        appendfsync = re.search(appendfsync, redis_conf)
        if not appendfsync:
            return public.returnMsg(False, "No parameter [ appendfsync ] in the redis configuration file")
        appendfsync=appendfsync.group(1)
        result["aof"] = {"appendonly":appendonly,"appendfsync":appendfsync}
        print(result)
        return result
    # 设置持久化配置
    def SetRedisPersistence(self,get):
        # 设置RDB持久化
        redis_conf = public.readFile(self.__redis_conf_file)
        conflist = []
        getdict = get.__dict__
        for i in getdict.keys():
            if i != "__module__" and i != "__doc__" and i != "data" and i != "args" and i != "action" and i !="name" and i != "s":
                getpost = {
                    "name": i,
                    "value": str(getdict[i])
                }
                conflist.append(getpost)
        print(conflist)
        for c in conflist:
            rep = "\n%s\s+[\w\.\/]+" % c["name"]
            if re.search(rep,redis_conf):
                if c["name"] == "dir":
                    if c["value"][-1] == "/":
                        c["value"] = c["value"][:-1]
                    c["value"] = c["value"] + "/redis_cache"
                    os.system("mkdir -p %s" % c["value"])
                    os.system("chown redis.redis %s" % c["value"])
                new_conf = "\n%s %s" % (c["name"],c["value"])
                redis_conf = re.sub(rep,new_conf,redis_conf)
            else:
                newrdb = ""
                if c["name"] == "rdb":
                    n = 0
                    for v in json.loads(c["value"]):
                        try:
                            if int(v["keys"]) == 0 and int(v["time"]) == 0:
                                n+=1
                        except:
                            return public.returnMsg(False, 'RDB_ERR')
                        newrdb += "\nsave %s %s" % (v["keys"], v["time"])
                    newrdb += "\n"
                    if n != 0:
                        newrdb = '\nsave ""\n'
                    rep = "\nsave[\w\s\n\"]+"
                    redis_conf = re.sub(rep, newrdb, redis_conf)

                else:
                    if c["value"] != "":
                        rep = "# Redis configuration file example.\n"
                        new_conf = "%s %s\n" % (c["name"], c["value"])
                        redis_conf = re.sub(rep, "%s%s" % (rep,new_conf), redis_conf)

        public.writeFile(self.__redis_conf_file,redis_conf)
        return public.returnMsg(True, 'The setting is successful. After restarting redis manually, it takes effect.')
    #取redis状态
    def GetRedisStatus(self,get):
        import re
        c = public.readFile('/www/server/redis/redis.conf')
        ip = re.search('\n\s*bind\s+([\d\.]+)',c)
        if not ip:
            return public.returnMsg(False,"No parameter [ bind ip ] in the redis configuration file")
        ip = ip.group(1)
        port = re.findall('\n\s*port\s+(\d+)',c)
        if not port:
            return public.returnMsg(False, "No parameter [ port ] in the redis configuration file")
        port = port[0]
        password = re.findall('\n\s*requirepass\s+(.+)',c)
        if password:
            password = ' -a ' + password[0]
        else:
            password = ''
        data = public.ExecShell('/www/server/redis/src/redis-cli -h ' + ip + ' -p ' + port + password + ' info')[0]
        res = [
               'tcp_port',
               'uptime_in_days',    #已运行天数
               'connected_clients', #连接的客户端数量
               'used_memory',       #Redis已分配的内存总量
               'used_memory_rss',   #Redis占用的系统内存总量
               'used_memory_peak',  #Redis所用内存的高峰值
               'mem_fragmentation_ratio',   #内存碎片比率
               'total_connections_received',#运行以来连接过的客户端的总数量
               'total_commands_processed',  #运行以来执行过的命令的总数量
               'instantaneous_ops_per_sec', #服务器每秒钟执行的命令数量
               'keyspace_hits',             #查找数据库键成功的次数
               'keyspace_misses',           #查找数据库键失败的次数
               'latest_fork_usec'           #最近一次 fork() 操作耗费的毫秒数
               ]
        data = data.split("\n")
        result = {}
        for d in data:
            if len(d)<3: continue;
            t = d.strip().split(':')
            if not t[0] in res: continue
            result[t[0]] = t[1]
        return result

    # 取文件配置
    def GetRedisFile(self,get):
        import files
        f = files.files()
        return f.GetFileBody(get)

    # 保存文件配置
    def SaveRedisFile(self,get):
        import files
        f = files.files()
        return f.SaveFileBody(get)
