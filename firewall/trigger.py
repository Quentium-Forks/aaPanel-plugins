#!/usr/bin/env python
# -*- coding:utf-8 -*-
 
import sqlite3,os,time,sys
import traceback
os.chdir("/www/server/panel")
sys.path.append("class/")
import public


class Sqlite():
    db_file = None     # 数据库文件
    connection = None  # 数据库连接对象
     
    def __init__(self):
        self.db_file = "/www/server/panel/data/default.db"
        self.create_table()

    # 获取数据库对象
    def GetConn(self):
        try:
            if self.connection == None:
                self.connection = sqlite3.connect(self.db_file)
                self.connection.text_factory = str
        except Exception as ex:
            traceback.print_exc()
            return "error: " + str(ex)
            
    def create_table(self):
        # 创建firewall_new表记录端口规则
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'firewall_new')).count():
            public.M('').execute('''CREATE TABLE "firewall_new" (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "protocol" TEXT DEFAULT '',
                "ports" TEXT,
                "types" TEXT,
                "address" TEXT DEFAULT '',
                "brief" TEXT DEFAULT '',
                "addtime" TEXT DEFAULT '');''')
            public.M('').execute('CREATE INDEX firewall_new_port ON firewall_new (ports);')

        # 创建firewall_ip表记录IP规则（屏蔽或放行）
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'firewall_ip')).count():
            public.M('').execute('''CREATE TABLE "firewall_ip" (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "types" TEXT,
                "address" TEXT DEFAULT '',
                "brief" TEXT DEFAULT '',
                "addtime" TEXT DEFAULT '');''')
            public.M('').execute('CREATE INDEX firewall_ip_addr ON firewall_ip (address);')

        # 创建firewall_trans表记录端口转发记录
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'firewall_trans')).count():
            public.M('').execute('''CREATE TABLE firewall_trans (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "start_port" TEXT,
                "ended_ip" TEXT,
                "ended_port" TEXT,
                "protocol" TEXT DEFAULT '',
                "addtime" TEXT DEFAULT '');''')
            public.M('').execute('CREATE INDEX firewall_trans_port ON firewall_trans (start_port);')

        # 创建firewall_country表记录IP规则（屏蔽或放行）
        if not public.M('sqlite_master').where('type=? AND name=?', ('table', 'firewall_country')).count():
            public.M('').execute('''CREATE TABLE "firewall_country" (
                "id" INTEGER PRIMARY KEY AUTOINCREMENT,
                "types" TEXT,
                "country" TEXT DEFAULT '',
                "brief" TEXT DEFAULT '',
                "addtime" TEXT DEFAULT '');''')
            public.M('').execute('CREATE INDEX firewall_country_name ON firewall_country (country);')
        # 修复之前已经创建的 firewall_country 表无 ports 字段的问题
        create_table_str = public.M('sqlite_master').where('type=? AND name=?', ('table', 'firewall_country')).getField('sql')
        if 'ports' not in create_table_str:
            public.M('').execute('ALTER TABLE "firewall_country" ADD "ports" TEXT DEFAULT ""')

    def create_trigger(self, sql):
        self.GetConn()
        self.connection.text_factory = str
        try:
            result = self.connection.execute(sql)
            id = result.lastrowid
            self.connection.commit()
            self.rm_lock()
            return id
        except Exception as ex:
            return "error: " + str(ex)

sql = """
        CREATE TRIGGER update_port AFTER DELETE ON firewall
        when old.port!=''
        BEGIN
            delete from firewall_new where ports = old.port;
            delete from firewall_ip where address = old.port;
        END;
      """
s = Sqlite()
s.create_trigger(sql)