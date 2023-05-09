#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: hezhihong <bt_ahong@qq.com>
# +-------------------------------------------------------------------

# +--------------------------------------------------------------------
# |   postgresql管理器
# +--------------------------------------------------------------------
import sys, os, json, re, time

# 设置运行目录
os.chdir("/www/server/panel")

# 添加包引用位置并引用公共包
sys.path.append("class/")
import public, files


# 在非命令行模式下引用面板缓存和session对象
if __name__ != '__main__':
    from BTPanel import cache, session


class pgsql_manager_main:
    __plugin_path = "/www/server/panel/plugin/pgsql_manager/"
    __config = None
    __soft_path = '/www/server/pgsql'

    # 构造方法
    def __init__(self):
        self.dbuser_info_path = "/www/server/panel/plugin/pgsql_manager_dbuser_info.json"
        self.db_back_dir = "/www/backup/pgsql_bak"
        if not os.path.isdir(self.db_back_dir):
            public.ExecShell("mkdir -p {}/upload".format(self.db_back_dir))
        u_bashrc = '/home/postgres/.bashrc'
        if os.path.exists(u_bashrc): os.remove(u_bashrc)

    def get_data(self, args):  # 获取测试数据
        # 处理前端传过来的参数
        if not 'p' in args: args.p = 1
        if not 'rows' in args: args.rows = 12
        if not 'callback' in args: args.callback = ''
        args.p = int(args.p)
        args.rows = int(args.rows)
        # 返回数据到前端
        return {'data': "Test data returned by the backend"}

    def get_service(self, args):  # 获取服务状态
        # 处理前端传过来的参数
        args = self.processing_parameter(args)
        shell_str = '''netstat -luntp|grep postgres'''
        result = public.ExecShell(shell_str)[0]
        if result:
            result = "Running"
            status = 1

        else:
            result = "Stopped"
            status = 0
        # 返回数据到前端
        return {'data': [result, status], "status": True}

    def get_config(self, args):  # 获取配置文件信息
        # 处理前端传过来的参数
        args = self.processing_parameter(args)
        config_file_path = self.get_data_directory(args)['data'] + "/postgresql.conf"
        config_file_info = public.ReadFile(config_file_path.strip(), mode='r')
        # 返回数据到前端
        return {'data': config_file_info, "status": True}

    def save_conf(self, args):  # 保存配置文件
        # 处理前端传过来的参数
        args = self.processing_parameter(args)
        config_file_path = self.get_data_directory(args)['data'] + "/postgresql.conf"
        result = public.WriteFile(config_file_path.strip(), args.text_conf, mode='w')
        # 返回数据到前端
        return {'data': "Save Successfully", "status": True}

    def get_clint_config(self, args):  # 获取 pg_hba.conf 客户端认证配置文件
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        config_file_path = self.get_data_directory(args)['data'] + "/pg_hba.conf"
        config_file_info = public.ReadFile(config_file_path.strip(), mode='r')
        # 返回数据到前端
        return {'data': config_file_info, "status": True}

    def save_get_clint_conf(self, args):  # 保存 pg_hba.conf 客户端认证配置文件
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        config_file_path = self.get_data_directory(args)['data'] + "/pg_hba.conf"
        public.WriteFile(config_file_path.strip(), args.text_conf, mode='w')
        public.ExecShell("/etc/init.d/pgsql reload")
        # 返回数据到前端
        return {'data': "Save Successfully", "status": True}

    def get_database_list(self, args):  # 获取数据库名称列表
        dbuser_info_path = self.dbuser_info_path
        data = []
        if os.path.isfile(dbuser_info_path):
            with open(dbuser_info_path) as f:
                for i in f:
                    if not i.strip(): continue
                    data.append(json.loads(i))
        data.reverse()
        # 返回数据到前端
        return {'data': data, "status": True}

    def create_user(self, args):  # 创建数据库和用户
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        listen_ip = args.listen_ip
        database = args.database
        error_motd =' The user name or database name cannot be a pure number!'
        error_motd_two='The username or database name cannot start with a number!'
        if args.username.isdigit():return {'data': error_motd, "status": False}
        if args.database.isdigit():return {'data': error_motd, "status": False}
        if args.username[0].isdigit():return {'data': error_motd_two, "status": False}
        if args.database[0].isdigit():return {'data': error_motd_two, "status": False}
        if not re.match("(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+", listen_ip.strip()):
            return {'data': "The permissions you entered are not legal and the addition failed!", "status": False}
        if listen_ip.strip() not in ["127.0.0.1/32", "localhost", "127.0.0.1"]:
            self.sed_conf("listen_addresses", "'*'")  # 修改监听所有地址
            public.ExecShell("/etc/init.d/pgsql restart")
        dbuser_info_path = self.dbuser_info_path
        if os.path.isfile(dbuser_info_path):
            with open(dbuser_info_path) as f:
                for i in f:
                    if not i.strip(): continue
                    if json.loads(i)['database'] == args.database:
                        return {'data': "The database already exists", "status": False}
                    if json.loads(i)['username'] == args.username:
                        return {'data': "User already exists", "status": False}
        dbuser_info = {"database": database, "username": args.username, "password": args.password, "listen_ip": listen_ip}
        public.WriteFile(dbuser_info_path, json.dumps(dbuser_info) + "\n", mode='a')

        port = self.get_port(args)['data']
        public.ExecShell('''echo "create database  {} ;"|su - postgres -c "/www/server/pgsql/bin/psql -p {}" '''.format(args.database, port))
        public.ExecShell('''echo "create user {};"|su - postgres -c "/www/server/pgsql/bin/psql -p {}" '''.format(args.username, port))
        public.ExecShell('''echo "alter user {} with password '{}';"|su - postgres -c "/www/server/pgsql/bin/psql -p {}" '''.format(args.username, args.password, port))
        public.ExecShell('''echo "GRANT ALL PRIVILEGES ON DATABASE {} TO {};"|su - postgres -c "/www/server/pgsql/bin/psql -p {}" '''.format(args.database, args.username, port))
        config_file_path = self.get_data_directory(args)['data'] + "/pg_hba.conf"
        public.WriteFile(config_file_path.strip(), "\nhost    {}  {}    {}    md5".format(args.database, args.username, args.listen_ip), mode='a')
        public.ExecShell("/etc/init.d/pgsql reload")
        # 返回数据到前端
        return {'data': "Created successfully", "status": True}

    def get_data_directory(self, args):  # 获取储存路径
        if os.path.isfile("/www/server/pgsql/data_directory"):
            data_directory = public.ReadFile("/www/server/pgsql/data_directory", mode='r')
        else:
            data_directory = "/www/server/pgsql/data"
        # 返回数据到前端
        return {'data': data_directory.strip(), "status": True}

    def modify_data_directory(self, args):  # 修改储存路径
        # 处理前端传过来的参数
        args = self.processing_parameter(args)
        old_data_directory = self.get_data_directory(args)['data']
        new_data_directory = args.data_directory
        if not files.files().CheckDir(new_data_directory) or not str(new_data_directory).strip().startswith("/"):
            return {'data': "The directory you submitted is invalid and the migration failed.", "status": False}
        public.ExecShell("mkdir -p {}".format(new_data_directory))
        public.ExecShell("/etc/init.d/pgsql stop")
        public.ExecShell('''cp -ar {}/* {} '''.format(old_data_directory, new_data_directory))
        public.ExecShell('''chown -R postgres:postgres {}'''.format(new_data_directory))
        public.ExecShell('''chmod -R 700 {} '''.format(new_data_directory))
        public.ExecShell('''chmod 777 /www/server/pgsql/logs/pgsql.log ''')
        public.WriteFile("/www/server/pgsql/data_directory", new_data_directory, mode='w')
        public.ExecShell("/etc/init.d/pgsql start")
        # 返回数据到前端
        return {'data': "Migration successful", "status": True}

    def get_port(self, args):  # 获取端口号
        str_shell = '''netstat -luntp|grep postgres|head -1|awk '{print $4}'|awk -F: '{print $NF}' '''
        port = public.ExecShell(str_shell)[0]
        if port.strip():
            return {'data': port.strip(), "status": True}
        else:
            return {'data': 5372, "status": False}

    def save_port(self, args):  # 修改端口
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        port = args.port
        check_port = [1,
                      5,
                      7,
                      9,
                      11,
                      13,
                      17,
                      18,
                      19,
                      20,
                      21,
                      22,
                      23,
                      25,
                      37,
                      39,
                      42,
                      43,
                      49,
                      50,
                      53,
                      63,
                      67,
                      68,
                      69,
                      70,
                      71,
                      72,
                      73,
                      73,
                      79,
                      80,
                      88,
                      95,
                      101,
                      102,
                      105,
                      107,
                      109,
                      110,
                      111,
                      113,
                      115,
                      117,
                      119,
                      123,
                      137,
                      138,
                      139,
                      143,
                      161,
                      162,
                      163,
                      164,
                      174,
                      177,
                      178,
                      179,
                      191,
                      194,
                      199,
                      201,
                      202,
                      204,
                      206,
                      209,
                      210,
                      213,
                      220,
                      245,
                      347,
                      363,
                      369,
                      370,
                      372,
                      389,
                      427,
                      434,
                      435,
                      443,
                      444,
                      445,
                      464,
                      468,
                      487,
                      488,
                      496,
                      500,
                      535,
                      538,
                      546,
                      547,
                      554,
                      563,
                      565,
                      587,
                      610,
                      611,
                      612,
                      631,
                      636,
                      674,
                      694,
                      749,
                      750,
                      765,
                      767,
                      873,
                      992,
                      993,
                      994,
                      995, ]
        if public.ExecShell('''netstat -luntp|grep %s''' % (port))[0].strip() or int(port) > 65534 or int(port) in check_port:
            return {'data': "This port number cannot be used and the modification failed.", "status": False}

        self.sed_conf("port", port)
        str_shell = '''/etc/init.d/pgsql restart '''  # 重启
        public.ExecShell(str_shell)
        # 返回数据到前端
        return {'data': "Modified successfully", "status": True}

    def get_unit(self, args):  # 获取单位
        unit = ''
        if "GB" in args:
            unit = "GB"
        elif "MB" in args:
            unit = "MB"
        elif "KB" in args:
            unit = "KB"
        elif "kB" in args:
            unit = "kB"
        return unit

    def get_pgsql_current_status(self, args):  # 获取pgsql当前状态
        port = self.get_port(args)['data']
        data_directory = self.get_data_directory(args)['data']
        data = {}
        data['Num of pgsql processes'] = public.ExecShell("ps -ef |grep postgres |wc -l")[0]
        data['Total connections'] = public.ExecShell('''echo "SELECT count(*) FROM pg_stat_activity WHERE NOT pid=pg_backend_pid();"|su - postgres -c "/www/server/pgsql/bin/psql -p {}"|sed -n 3p '''.format(port))[0]
        # data['当前正在执行sql数量'] = public.ExecShell('''echo "select count(*) from pg_stat_activity where state='active';"|su - postgres -c "/www/server/pgsql/bin/psql -p {}"|sed -n 3p '''.format(port))[0]
        data['DB size'] = public.ExecShell('''echo "select pg_size_pretty(pg_database_size('postgres'));"|su - postgres -c "/www/server/pgsql/bin/psql -p {}"|sed -n 3p '''.format(port))[0]
        data['Start Time'] = public.ExecShell('''cat {}/postmaster.pid |sed -n 3p '''.format(data_directory))[0]
        timestamp = data['Start Time']
        time_local = time.localtime(int(timestamp))
        dt = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
        data['Start Time'] = dt
        data['PID'] = public.ExecShell('''cat {}/postmaster.pid |sed -n 1p '''.format(data_directory))[0]
        data['Used memory'] = public.ExecShell('''cat /proc/%s/status|grep VmRSS|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['The size of the physical memory that the table process has locked'] = public.ExecShell('''cat /proc/%s/status|grep VmLck|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['Peak of physical memory'] = public.ExecShell('''cat /proc/%s/status|grep VmHWM|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['Data segment size'] = public.ExecShell('''cat /proc/%s/status|grep VmData|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['Stack segment size'] = public.ExecShell('''cat /proc/%s/status|grep VmStk|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['Code size'] = public.ExecShell('''cat /proc/%s/status|grep VmExe|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['The size of the LIB library'] = public.ExecShell('''cat /proc/%s/status|grep VmLib|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['Occupy the size of Swap'] = public.ExecShell('''cat /proc/%s/status|grep VmSwap|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['Occupied page table size'] = public.ExecShell('''cat /proc/%s/status|grep VmPTE|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]
        data['Number of current pending signals'] = public.ExecShell('''cat /proc/%s/status|grep SigQ|awk -F: '{print $2}'  ''' % (data['PID'].strip()))[0]

        # 返回数据到前端
        return {'data': data, "status": True}

    def get_pgsql_status(self, args):  # 获取pgsql性能信息
        args = self.processing_parameter(args)
        data_directory = self.get_data_directory(args)['data'].strip()
        data = {}
        shared_buffers, work_mem, effective_cache_size, maintence_work_mem, max_connections, temp_buffers, max_prepared_transactions, max_stack_depth, bgwriter_lru_maxpages, max_worker_processes, listen_addresses = '', '', '', '', '', '', '', '', '', '', ''
        with open("{}/postgresql.conf".format(data_directory)) as f:
            for i in f:
                if i.strip().startswith("shared_buffers"):
                    shared_buffers = i.split("=")[1]
                elif i.strip().startswith("#shared_buffers"):
                    shared_buffers = i.split("=")[1]
                shared_buffers_num = re.match('\d+', shared_buffers.strip()).group() if re.match('\d+', shared_buffers.strip()) else ""
                data['shared_buffers'] = [shared_buffers_num, "MB", "PGsql interacts with the kernel and disk through shared_buffers."]

                if i.strip().startswith("work_mem"):
                    work_mem = i.split("=")[1]
                elif i.strip().startswith("#work_mem"):
                    work_mem = i.split("=")[1]
                work_mem_num = re.match('\d+', work_mem.strip()).group() if re.match('\d+', work_mem.strip()) else ""
                data['work_mem'] = [work_mem_num, "MB", "Increasing work_mem helps increase the speed of sorting."]

                if i.strip().startswith("effective_cache_size"):
                    effective_cache_size = i.split("=")[1]
                elif i.strip().startswith("#effective_cache_size"):
                    effective_cache_size = i.split("=")[1]
                effective_cache_size_num = re.match('\d+', effective_cache_size.strip()).group() if re.match('\d+', effective_cache_size.strip()) else ""
                data['effective_cache_size'] = [effective_cache_size_num, "GB", "The maximum cache that pgsql can use, such as 4G memory."]

                if i.strip().startswith("temp_buffers "):
                    temp_buffers = i.split("=")[1]
                elif i.strip().startswith("#temp_buffers "):
                    temp_buffers = i.split("=")[1]
                temp_buffers_num = re.match('\d+', temp_buffers.strip()).group() if re.match('\d+', temp_buffers.strip()) else ""
                data['temp_buffers'] = [temp_buffers_num, "MB", "The maximum of temp_buffers used by each database session."]

                if i.strip().startswith("max_connections"):
                    max_connections = i.split("=")[1]
                elif i.strip().startswith("#max_connections"):
                    max_connections = i.split("=")[1]
                max_connections_num = re.match('\d+', max_connections.strip()).group() if re.match('\d+', max_connections.strip()) else ""
                data['max_connections'] = [max_connections_num, self.get_unit(max_connections), "Maximum number of connections"]

                if i.strip().startswith("max_prepared_transactions"):
                    max_prepared_transactions = i.split("=")[1]
                elif i.strip().startswith("#max_prepared_transactions"):
                    max_prepared_transactions = i.split("=")[1]
                max_prepared_transactions_num = re.match('\d+', max_prepared_transactions.strip()).group() if re.match('\d+', max_prepared_transactions.strip()) else ""
                data['max_prepared_transactions'] = [max_prepared_transactions_num, self.get_unit(max_prepared_transactions), "The maximum of transactions can in prepared state at the same time"]

                if i.strip().startswith("max_stack_depth "):
                    max_stack_depth = i.split("=")[1]
                elif i.strip().startswith("#max_stack_depth "):
                    max_stack_depth = i.split("=")[1]
                max_stack_depth_num = re.match('\d+', max_stack_depth.strip()).group() if re.match('\d+', max_stack_depth.strip()) else ""
                data['max_stack_depth'] = [max_stack_depth_num, "MB", "The maximum security depth of the server's execution stack."]

                if i.strip().startswith("bgwriter_lru_maxpages "):
                    bgwriter_lru_maxpages = i.split("=")[1]
                elif i.strip().startswith("#bgwriter_lru_maxpages "):
                    bgwriter_lru_maxpages = i.split("=")[1]
                bgwriter_lru_maxpages_num = re.match('\d+', bgwriter_lru_maxpages.strip()).group() if re.match('\d+', bgwriter_lru_maxpages.strip()) else ""
                data['bgwriter_lru_maxpages'] = [bgwriter_lru_maxpages_num, "", "How many dirty pages are written in one cycle"]

                if i.strip().startswith("max_worker_processes "):
                    max_worker_processes = i.split("=")[1]
                elif i.strip().startswith("#max_worker_processes "):
                    max_worker_processes = i.split("=")[1]
                max_worker_processes_num = re.match('\d+', max_worker_processes.strip()).group() if re.match('\d+', max_worker_processes.strip()) else ""
                data['max_worker_processes'] = [max_worker_processes_num, "", "Can allow up to how many worker processes fork."]

                if i.strip().startswith("listen_addresses"):
                    listen_addresses = i.split("=")[1]
                elif i.strip().startswith("#listen_addresses"):
                    listen_addresses = i.split("=")[1]
                listen_addresses = re.match("\'.*?\'", listen_addresses.strip()).group() if re.match("\'.*?\'", listen_addresses.strip()) else ""
                data['listen_addresses'] = [listen_addresses.replace("'", '').replace("127.0.0.1", 'localhost'), "", "Pgsql listen address"]

        # 返回数据到前端
        data['status'] = True
        return data

    def sed_conf(self, name, val):  # 替换配置文件
        data_directory = self.get_data_directory("")['data'].strip()
        modify = ''
        conf_str = ''
        with open("{}/postgresql.conf".format(data_directory)) as f:
            for i in f:
                if i.strip().startswith(name):
                    i = "{} = {} \n".format(name, val)
                    modify = True
                conf_str += i
        public.WriteFile("{}/postgresql.conf".format(data_directory), conf_str, mode='w')
        if not modify:
            public.WriteFile("{}/postgresql.conf".format(data_directory), "\n{} = {}".format(name, val), mode='a+')

    def save_pgsql_status(self, args):  # 保存pgsql性能调整信息
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        for k, v in json.loads(args.status_data).items():
            if not v: continue
            if k.strip() == "listen_addresses":
                v = "'{}'".format(v.replace("'", ''))
            self.sed_conf(k, v)
        # 返回数据到前端
        return {'data': "Saved Successfully", "status": True}

    def get_pgsql_log(self, args):  # 获取pgsql日志
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        result = public.ExecShell('''tail -100 /www/server/pgsql/logs/pgsql.log ''')[0]
        # 返回数据到前端
        return {'data': result, "status": True}

    def get_slow_pgsql_log(self, args):  # pgsql慢日志查询
        result = public.ExecShell('''tail -100 /www/server/pgsql/logs/{}'''.format(time.strftime("postgresql-%Y-%m-%d.log")))[0]
        # 返回数据到前端
        return {'data': result, "status": True}

    def pgsql_back(self, args):  # 备份数据库
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        port = self.get_port(args)['data']
        shell_str = '''su - postgres -c "/www/server/pgsql/bin/pg_dump -c {} -p {} "| gzip > {}/{}_{}.gz '''.format(args.database, port, self.db_back_dir, args.database, time.strftime("%Y%m%d_%H%M%S"))
        public.ExecShell(shell_str)

        # 返回数据到前端
        return {'data': "Backup Successfully", "status": True}

    def get_pgsql_bak_list(self, args):  # 获取数据库备份文件列表
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        file_list = os.listdir(self.db_back_dir)
        file_list_json = []
        for i in file_list:
            if i.split("_")[0].startswith(args.database):
                file_path = os.path.join(self.db_back_dir, i)
                file_info = os.stat(file_path)
                create_time = file_info.st_ctime
                time_local = time.localtime(int(create_time))
                create_time = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
                file_size = file_info.st_size
                file_size = public.to_size(file_size)
                file_list_json.append({"filename": i, "create_time": create_time, "file_size": file_size, "file_path": file_path})

        # 返回数据到前端
        return {'data': file_list_json, "status": True}

    def del_pgsql_db(self, args):  # 删除数据库
        del_info = ''
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        port = self.get_port(args)['data']
        database = args.database
        del_bak = args.del_bak
        if int(del_bak) == 1:
            public.ExecShell("rm -rf {}_*".format(os.path.join(self.db_back_dir, database)))
            del_info += 'Delete backup file successfully  '
        public.ExecShell('''echo "drop database {};"|su - postgres -c "/www/server/pgsql/bin/psql  -p {} " '''.format(database, port))
        dbuser_info_path = self.dbuser_info_path
        dbuser_info = ''
        if os.path.isfile(dbuser_info_path):
            with open(dbuser_info_path) as f:
                for i in f:
                    if not i.strip(): continue
                    if json.loads(i)['database'] == database:
                        public.ExecShell('''echo "drop user {};"|su - postgres -c "/www/server/pgsql/bin/psql  -p {} " '''.format(json.loads(i)['username'], port))
                        continue
                    dbuser_info += i
        public.WriteFile(dbuser_info_path, dbuser_info, mode='w')
        # 删除客户端认证相关配置
        config_file_path = self.get_data_directory(args)['data'] + "/pg_hba.conf"
        old_config = public.ReadFile(config_file_path)
        new_config = re.sub(r'host\s*{}.*'.format(database), '', old_config).strip()
        public.WriteFile(config_file_path, new_config)
        public.ExecShell("/etc/init.d/pgsql reload")
        # 返回数据到前端
        return {'data': del_info + "Delete database successfully", "status": True}

    def del_pgsql_bak(self, args):  # 删除数据库备份文件
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        os.remove(os.path.join(self.db_back_dir, args.filename))
        # 返回数据到前端
        return {'data': "Delete backup file successfully", "status": True}

    def del_import_pgsql_bak(self, args):  # 删除导入的数据库备份文件
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        os.remove(os.path.join(self.db_back_dir, "upload", args.filename))
        # 返回数据到前端
        return {'data': "Delete backup file successfully", "status": True}

    def pgsql_restore(self, args):  # 恢复数据库
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        filename = args.filename
        file_path = os.path.join(self.db_back_dir, filename)
        if not os.path.exists(file_path): return public.returnMsg(False, '备份文件不存在')
        port = self.get_port(args)['data']
        dbname = filename.split("_")[0]
        public.ExecShell('''gunzip -c {}|su - postgres -c " /www/server/pgsql/bin/psql  -d {}  -p {} " '''.format(file_path, dbname, port))
        # 返回数据到前端
        return {'data': "Restore the database successfully", "status": True}

    def get_import_bak_list(self, args):  # 获取导入的文件列表
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        file_list = os.listdir(os.path.join(self.db_back_dir, "upload"))
        file_list_json = []
        for i in file_list:
            file_path = os.path.join(os.path.join(self.db_back_dir, "upload"), i)
            file_info = os.stat(file_path)
            create_time = file_info.st_ctime
            time_local = time.localtime(int(create_time))
            create_time = time.strftime("%Y-%m-%d %H:%M:%S", time_local)
            file_size = file_info.st_size
            file_size = public.to_size(file_size)
            file_list_json.append({"filename": i, "create_time": create_time, "file_size": file_size, "file_path": file_path})

        # 返回数据到前端
        return {'data': file_list_json, "status": True}

    def pgsql_back_import(self, args):  # 从本地导入文件恢复数据库
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        port = self.get_port(args)['data']
        filepath = args.filepath
        database = args.database
        with open(self.dbuser_info_path) as f:
            for i in f:
                if not i.strip(): continue
                if json.loads(i)['database'] == database:
                    username = json.loads(i)['username']
        if str(filepath).strip().endswith(".dmp") or str(filepath).strip().endswith(".sql"):
            result = public.ExecShell(r'''cat {}|sed s#OWNER\ TO#OWNER\ TO\ {}\;--#g|su - postgres -c "/www/server/pgsql/bin/psql  -d {}  -p {} "  '''.format(filepath, username, database, port, ))
        elif str(filepath).strip().endswith(".tar.gz"):
            result = public.ExecShell(r'''tar zxOf {}|sed s#OWNER\ TO#OWNER\ TO\ {}\;--#g|su - postgres -c "/www/server/pgsql/bin/psql  -d {}  -p {} " '''.format(filepath, username, database, port))
        elif str(filepath).strip().endswith(".gz"):
            result = public.ExecShell(r'''gunzip -c {}|sed s#OWNER\ TO#OWNER\ TO\ {}\;--#g|su - postgres -c "/www/server/pgsql/bin/psql  -d {}  -p {} " '''.format(filepath, username, database, port))
        elif str(filepath).strip().endswith(".zip"):
            result = public.ExecShell(r'''unzip -c {}|sed s#OWNER\ TO#OWNER\ TO\ {}\;--#g|su - postgres -c "/www/server/pgsql/bin/psql  -d {}  -p {} " '''.format(filepath, username, database, port))
        else:
            return {'data': "File format is incorrect", "status": False}
        # public.ExecShell('''echo "GRANT ALL PRIVILEGES ON DATABASE {} TO {};"|su - postgres -c "/www/server/pgsql/bin/psql -p {}" '''.format(database, username, port))
        # 返回数据到前端
        # if result[1]:
        #     return {'msg': result[1], "status": False}
        return {'data': "Restore database {} success!".format(database), "status": True}

    def modify_pgsql_password(self, args):  # 修改pgsql密码
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        username = args.username
        password = args.password
        port = self.get_port(args)['data']
        dbuser_info_path = self.dbuser_info_path
        dbuser_info_str = ''
        if os.path.isfile(dbuser_info_path):
            with open(dbuser_info_path) as f:
                for i in f:
                    if not i.strip(): continue
                    item = json.loads(i)
                    if item['username'] == username:
                        item['password'] = password
                        dbuser_info_str += json.dumps(item) + '\n'
                        continue
                    dbuser_info_str += i
        public.WriteFile(dbuser_info_path, dbuser_info_str, mode='w')
        public.ExecShell('''echo "alter user {} with password '{}';"|su - postgres -c "/www/server/pgsql/bin/psql -p {}" '''.format(args.username, args.password, port))

        # 返回数据到前端
        return {'data': "Password reset complete", "status": True}

    def modify_pgsql_listen_ip(self, args):  # 修改pgsql用户访问权限
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        username = args.username
        listen_ip = args.listen_ip
        if not re.match(r"(?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+", listen_ip.strip()):
            return {'data': "The input you entered is illegal and the modification failed.", "status": False}
        dbuser_info_path = self.dbuser_info_path
        dbuser_info_str = ''
        if os.path.isfile(dbuser_info_path):
            with open(dbuser_info_path) as f:
                for i in f:
                    if not i.strip(): continue
                    item = json.loads(i)
                    if item['username'] == username:
                        item['listen_ip'] = listen_ip
                        database = item['database']
                        dbuser_info_str += json.dumps(item) + '\n'
                        continue
                    dbuser_info_str += i
        public.WriteFile(dbuser_info_path, dbuser_info_str, mode='w')
        config_file_path = os.path.join(self.get_data_directory(args)['data'], "pg_hba.conf").strip()
        con_str = public.ReadFile(config_file_path).strip() + '\n'
        head_index = '# PostgreSQL Client Authentication Configuration File'
        tmp_1 = re.search(head_index + r"(\n|.)+" + head_index,con_str)
        if tmp_1:
            con_str = con_str.replace(tmp_1.group(),head_index)
        tmp = re.search(r"(host\s+"+database+r"\s+"+username+r"\s+[\d\./]+\s+\w+)",con_str)
        host_str = "host    {}   {}    {}    md5\n".format(database, username, listen_ip)
        if tmp:
            sub_str = tmp.group()
            con_str = con_str.replace(sub_str,host_str).strip()
        else:
            con_str = con_str.strip()
            con_str += "\n" + host_str
        public.WriteFile(config_file_path, con_str.replace('\n\nhost','\nhost').strip() + '\n')
        public.ExecShell("/etc/init.d/pgsql reload")
        # 返回数据到前端
        return {'data': "Modify pgsql user access rights successfully", "status": True}

    def Install_uninstall(self, args):  # 安装卸载pgsql
        args = self.processing_parameter(args)  # 处理前端传过来的参数
        if 'pgsql_unInstall' not in args: args.pgsql_unInstall = 0
        if 'get_pgsql_version' not in args: args.get_pgsql_version = 0
        if 'get_pgsql_install_info' not in args: args.get_pgsql_install_info = 0
        if 'get_pgsql_install_log' not in args: args.get_pgsql_install_log = 0
        if 'del_bak' not in args: args.del_bak = 0
        if int(args.get_pgsql_install_log) != 0:
            result = public.ExecShell('''tail  /tmp/pgsql_install.log ''')[0]
            # 返回数据到前端
            return {'data': result, "status": True}

        if int(args.get_pgsql_version) != 0 and int(args.get_pgsql_install_info) != 0:
            import requests
            result = requests.get('https://endoflife.date/api/postgresql.json')
            parsed_result = result.json()
            pgsql_install_info = [{"pgsql_version": "postgresql " + x['latest'], "down_url": "https://ftp.postgresql.org/pub/source/v" + x['latest'] + "/postgresql-15.2.tar.gz"} for x in parsed_result]
            pgsql_version = public.ExecShell('''/www/server/pgsql/bin/psql --version''')[0]
            if pgsql_version.strip():
                is_install = "Already installed"
            else:
                is_install = "Not Installed"
            return {'data': {"pgsql_install_info": pgsql_install_info, "pgsql_version": pgsql_version, "is_install": is_install}, "status": True}

        if args.pgsql_unInstall != 0:
            if int(args.del_bak) == 1: public.ExecShell("rm -rf {}".format(self.db_back_dir))
            public.ExecShell('''netstat -luntp|grep postgres|awk '{print $NF}'|awk -F/ '{print "kill -9 "$1}'|sh ''')
            public.ExecShell("rm -rf /www/server/pgsql && rm -rf /usr/local/pgsql && rm -rf {}".format(self.dbuser_info_path))
            return {'data': "Pgsql has been uninstalled successfully", "status": True}

        pgsql_version = args.pgsql_version.split("/")[-1]
        down_url = args.pgsql_version
        if os.path.isdir("/www/server/pgsql/bin"):
            return {'data': "Pgsql has been installed", "status": True}
        public.ExecShell(''' nohup sh /www/server/panel/plugin/pgsql_manager/pgsql_install.sh "{}" "{}" > /tmp/pgsql_install.log 2>&1 &  '''.format(pgsql_version, down_url))
        # 返回数据到前端
        return {'data': "{} Installing, please wait!".format(pgsql_version), "status": True}

    def processing_parameter(self, args):  # 处理前端传过来的参数
        if 'p' not in args: args.p = 1
        if 'rows' not in args: args.rows = 12
        if 'callback' not in args: args.callback = ''
        args.p = int(args.p)
        args.rows = int(args.rows)
        return args

    # 读取配置项(插件自身的配置文件)
    # @param key 取指定配置项，若不传则取所有配置[可选]
    # @param force 强制从文件重新读取配置项[可选]
    def __get_config(self, key=None, force=False):
        # 判断是否从文件读取配置
        if not self.__config or force:
            config_file = self.__plugin_path + 'config.json'
            if not os.path.exists(config_file): return None
            f_body = public.ReadFile(config_file)
            if not f_body: return None
            self.__config = json.loads(f_body)

        # 取指定配置项
        if key:
            if key in self.__config: return self.__config[key]
            return None
        return self.__config

    def get_root_password(self,args):
        """
        @获取sa密码
        """
        check_result = os.system('/www/server/pgsql/bin/psql --version')
        if check_result !=0:return public.returnMsg(False,'Detected that PgSQL is not installed or not started, please install or start it first')
        password = ''
        path =  '{}/data/postgresAS.json'.format(public.get_panel_path())
        if os.path.isfile(path):
            try:
                password = json.loads(public.readFile(path))['password']
            except :pass
        if 'is_True' in args and args.is_True:return password
        return public.returnMsg(True,password)

    def reset_password(self,args):
        """
        @设置sa密码
        """
        password = public.trim(args['password'])
        if len(password) < 8 : return public.returnMsg(False,'The password is entered incorrectly and cannot be less than 8 digits.')
        check_result = os.system('/www/server/pgsql/bin/psql --version')
        if check_result !=0:return public.returnMsg(False,'Detected that PgSQL is not installed or not started, please install or start it first')

        path = '{}/data/pg_hba.conf'.format(self.__soft_path)
        p_path = '{}/data/postgresAS.json'.format(public.get_panel_path())
        if not os.path.isfile(path):return public.returnMsg(False,'{} file does not exist, please check if the installation is complete!'.format(path))
        src_conf = public.readFile(path)
        add_conf = src_conf.replace('md5','trust')
        # public.writeFile(path,public.readFile(path).replace('md5','trust'))
        public.writeFile(path,add_conf)
        port = self.get_port(args)['data']
        public.ExecShell('''echo "alter user postgres with password '{}';"|su - postgres -c "/www/server/pgsql/bin/psql -p {}" '''.format(args.password, port))
        data = {"username":"postgres","password":""}
        try:
            data = json.loads(public.readFile(p_path))
        except : pass
        data['password'] = password
        public.writeFile(p_path,json.dumps(data))
        public.writeFile(path, src_conf)
        return public.returnMsg(True,'Admin password changed successfully.')

    # 设置配置项(插件自身的配置文件)
    # @param key 要被修改或添加的配置项[可选]
    # @param value 配置值[可选]
    def __set_config(self, key=None, value=None):
        # 是否需要初始化配置项
        if not self.__config: self.__config = {}

        # 是否需要设置配置值
        if key:
            self.__config[key] = value

        # 写入到配置文件
        config_file = self.__plugin_path + 'config.json'
        public.WriteFile(config_file, json.dumps(self.__config))
        return True
