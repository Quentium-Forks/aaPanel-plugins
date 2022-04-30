# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2099 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: zhaowen <zhw@bt.com>
# +-------------------------------------------------------------------

# +--------------------------------------------------------------------
# |   堡塔反垃圾邮件网关
# +--------------------------------------------------------------------
import sys,os,time

py_v = sys.version_info[0]
if py_v == 2:
    reload(sys)
    sys.setdefaultencoding('utf-8')
sys.path.append('/www/server/panel/class')
import pyinotify
from public import GetNumLines,readFile,writeFile,ExecShell
from json import loads,dumps

count_file = '/www/server/panel/plugin/anti_spam/data/count.json'
day_file = '/www/server/panel/plugin/anti_spam/data/{}.json'
cfgd = '/www/server/panel/plugin/anti_spam/data/'
monitor_log = '/var/log/amavis.log'

class MyEventHandler(pyinotify.ProcessEvent):

    def process_IN_MODIFY(self, event):
        process_record()



def process_record(line=1):
    data = GetNumLines(monitor_log, line)
    if "amavis" not in data:
        return
    rules = {
        'ban_file': 'Blocked BANNED',  # 匹配到禁止的附件
        'spam': 'SPAM',  # 垃圾邮件
        'virus': 'Blocked INFECTED'  # 已经阻止的病毒邮件
    }
    tmp = None
    for r in rules:
        if rules[r] in data:
            tmp = r
            break
    if tmp:
        process_conf(tmp)
        process_hour_conf(tmp)
        return True
    else:
        line += 1
        if line > 5:
            return
        process_record(line)

def init_conf():
    if not os.path.exists(cfgd):
        os.makedirs(cfgd)
    cfg = cfgd+'count.json'
    if not os.path.exists(cfg):
        conf = {'ban_file':0,'spam':0,'virus':0}
        writeFile(cfg,dumps(conf))
    else:
        try:
            conf = loads(readFile(cfg))
        except:
            conf = {'ban_file':0,'spam':0,'virus':0}
            writeFile(cfg, dumps(conf))
    return conf

def process_hour_conf(data=None):
    today = time.strftime("%Y-%m-%d", time.localtime())
    if not os.path.exists(cfgd):
        os.makedirs(cfgd)
    cfgf = cfgd + today + ".json"
    conf = readFile(cfgf)
    hour = time.strftime("%H", time.localtime())
    hour = hour[-1] if hour[0] == '0' else hour
    if not conf:
        conf = {'ban_file':{},'spam':{},'virus':{}}
        for t in range(1,25):
            conf['ban_file'][str(t)] = 0
            conf['spam'][str(t)] = 0
            conf['virus'][str(t)] = 0
        conf[data][hour] += 1
        writeFile(cfgf,dumps(conf))
    else:
        conf = {}
        try:
            conf = loads(readFile(cfgf))
            conf[data][hour] += 1
        except:
            for t in range(1, 25):
                conf[str(t)] = 0
            conf[data][hour] +=1
        writeFile(cfgf,dumps(conf))

def process_conf(data):
    conf = init_conf()
    conf[data] += 1
    writeFile(count_file,dumps(conf))

def run():
    if not os.path.exists(monitor_log):
        ExecShell('touch {0} && chown syslog.adm {0}'.format(monitor_log))
    init_conf()
    event = MyEventHandler()
    watchManager = pyinotify.WatchManager()
    mode = pyinotify.IN_MODIFY
    watchManager.add_watch(monitor_log, mode, auto_add=True, rec=True)
    notifier = pyinotify.Notifier(watchManager, event)
    notifier.loop()

if __name__ == '__main__':
    run()