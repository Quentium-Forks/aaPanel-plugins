#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
install_tmp='/tmp/bt_install.pl'
pluginPath=/www/server/panel/plugin/nodejs

public_file=/www/server/panel/install/public.sh
if [ ! -f $public_file ];then
	wget -O $public_file https://node.aapanel.com/install/public.sh -T 5;
fi
. $public_file

download_Url=$NODE_URL


Install_nodejs()
{
	mkdir -p $pluginPath

	wget --no-check-certificate -O $pluginPath/nodejs.zip $download_Url/install/plugin/nodejs_en/nodejs.zip -T 5

	cd $pluginPath
	unzip -o nodejs.zip -d /www/server/panel/plugin/
	rm -f nodejs.zip

	\cp -a -r /www/server/panel/plugin/nodejs/icon.png /www/server/panel/BTPanel/static/img/soft_ico/ico-nodejs.png
	echo 'Installation complete' > $install_tmp
}

Uninstall_nodejs()
{
	rm -rf $pluginPath
}


action=$1
if [ "${1}" == 'install' ];then
	Install_nodejs
else
	Uninstall_nodejs
fi
