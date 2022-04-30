#coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔Linux面板 x3
# +-------------------------------------------------------------------
# | Copyright (c) 2015-2017 宝塔软件(http://bt.cn) All rights reserved.
# +-------------------------------------------------------------------
# | Author: hwliang <hwl@bt.cn>
# +-------------------------------------------------------------------

#+--------------------------------------------------------------------
#|   宝塔WebHook插件
#+--------------------------------------------------------------------

import public,json,os,time
class obj: id=0
class webhook_main:
    __setupPath = 'plugin/webhook'
    __panelPath = '/www/server/panel'
    
    #获取列表
    def GetList(self,get):
        jsonFile = self.__setupPath + '/list.json'
        if not os.path.exists(jsonFile): return public.returnMsg(False,'Configuration file does not exist!')
        data = {}
        data = json.loads(public.readFile(jsonFile))
        return sorted(data, key= lambda b:b['addtime'],reverse=True)
    
    #添加HOOK
    def AddHook(self,get):
        data = self.GetList(get)
        if get.title == '' or get.shell == '': return public.returnMsg(False,'TITLE_HOOK_CANT_EMPTY')
        hook = {}
        hook['title'] = get.title
        hook['access_key'] = public.GetRandomString(48)
        hook['count'] = 0
        hook['addtime'] = int(time.time())
        hook['uptime'] = 0
        jsonFile = self.__setupPath + '/list.json'
        if self.__setupPath + '/script': os.system('mkdir ' + self.__setupPath + '/script')
        shellFile = self.__setupPath + '/script/' + hook['access_key']
        public.writeFile(shellFile,get.shell)
        data.append(hook)
        public.writeFile(jsonFile,json.dumps(data))
        return public.returnMsg(True,'ADD_SUCCESS')
    
    #删除Hook
    def DelHook(self,get):
        data = self.GetList(get)
        newdata = []
        for hook in data:
            if hook['access_key'] == get.access_key: continue
            newdata.append(hook)
        jsonFile = self.__setupPath + '/list.json'
        shellFile = self.__setupPath + '/script/' + get.access_key
        if not os.path.exists(shellFile):
            return public.returnMsg(False,'Delete Failed!')
        os.remove(shellFile)
        log_file = "{}.log".format(shellFile)
        if os.path.exists(log_file):
            os.remove(log_file)
        public.writeFile(jsonFile,json.dumps(newdata))
        return public.returnMsg(True,'DEL_SUCCESS')
    
    #运行Shell
    def RunShell(self,get):
        data = self.GetList(get)
        for i in range(len(data)):
            if data[i]['access_key'] == get.access_key:
                shellFile = self.__setupPath + '/script/' + get.access_key
                param = ''
                if hasattr(get,'param'): param = get.param
                os.system("bash {} \"{}\" >> {}.log &".format(shellFile,param.replace('"',r'\"'),shellFile))
                data[i]['count'] +=1
                data[i]['uptime'] = int(time.time())
                jsonFile = self.__setupPath + '/list.json'
                public.writeFile(jsonFile,json.dumps(data))
                return public.returnMsg(True,'RUN_SUCCESS')
        return public.returnMsg(False,'HOOK_NOT_EXIST')
    
    #运行Hook
    def RunHook(self,get):
        res = self.RunShell(get)
        result = {}
        result['code'] = 0
        if res['status']: result['code'] = 1
        return result
    