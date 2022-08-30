#!/bin/bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

download_Url=https://node.aapanel.com
pluginPath=/www/server/panel/plugin/cloud_dns


Install_ddns()
{
	en=''
	begin='正在安装脚本文件...'
	end='安装完成'
	grep "English" /www/server/panel/config/config.json >> /dev/null
	if [ "$?" -eq 0 ];then
		en='_en'
		begin='Installing script file...'
		end='The installation is complete'
	fi
	echo $begin
	mkdir -p $pluginPath
	wget -O $pluginPath/cloud_dns.zip $download_Url/install/plugin/cloud_dns$en/cloud_dns.zip -T 5
  cd $pluginPath && unzip cloud_dns.zip
	echo $end
}

Uninstall_ddns()
{
	rm -rf $pluginPath
}

if [ "${1}" == 'install' ];then
	Install_ddns
elif  [ "${1}" == 'update' ];then
	Install_ddns
elif [ "${1}" == 'uninstall' ];then
	Uninstall_ddns
fi
