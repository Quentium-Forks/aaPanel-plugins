#!/bin/bash
PATH=/www/server/panel/pyenv/bin:/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH
public_file=/www/server/panel/install/public.sh

if [ ! -f $public_file ];then
	wget -O $public_file http://download.bt.cn/install/public.sh -T 5;
fi

. $public_file
download_Url=$NODE_URL
install_tmp='/tmp/bt_install.pl'
pluginPath=/www/server/panel/plugin/free_waf
waf_path=/www/server/free_waf

Install_btwaf()
{	

	if [ -f /www/server/panel/vhost/nginx/btwaf.conf ];then
		rm -rf /www/server/panel/vhost/nginx/btwaf.conf
	fi
	mkdir -p $pluginPath
	Install_cjson
	mkdir -p $waf_path
	mkdir -p /www/wwwlogs/free_waf_log
	chmod 777 /www/wwwlogs/free_waf_log
	wget -O $pluginPath/free_waf_main.py $download_Url/install/plugin/free_waf_en/free_waf_main.py -T 5
	wget -O $pluginPath/index.html $download_Url/install/plugin/free_waf_en/index.html -T 5
	wget -O $pluginPath/info.json $download_Url/install/plugin/free_waf_en/info.json -T 5
	wget -O $pluginPath/icon.png $download_Url/install/plugin/free_waf_en/icon.png -T 5
	wget -O $pluginPath/rule.json $download_Url/install/plugin/free_waf_en/rule.json -T 5
	wget -O $pluginPath/webshell.log $download_Url/install/plugin/free_waf_en/webshell.log -T 5
	wget -O /www/server/panel/vhost/nginx/free_waf.conf $download_Url/install/plugin/free_waf_en/free_waf.conf -T 5

	\cp -a -r /www/server/panel/plugin/free_waf/icon.png  /www/server/panel/BTPanel/static/img/soft_ico/ico-free_waf.png
	wget -O $pluginPath/free_waf_data.zip $download_Url/install/plugin/free_waf_en/free_waf_data.zip -T 5
	unzip -o $pluginPath/free_waf_data.zip -d /tmp/ > /dev/null
	rm -f $pluginPath/free_waf_data.zip
	if [ ! -f $waf_path/html/get.html ];then
		mkdir $waf_path/html/
		\cp -a -r /tmp/free_waf/html/get.html $waf_path/html/get.html
		\cp -a -r /tmp/free_waf/html/get.html $waf_path/html/post.html
		\cp -a -r /tmp/free_waf/html/get.html $waf_path/html/cookie.html
		\cp -a -r /tmp/free_waf/html/get.html $waf_path/html/user_agent.html
		\cp -a -r /tmp/free_waf/html/get.html $waf_path/html/other.html
	fi
	if [ ! -f $waf_path/rule/url.json ];then
		mkdir $waf_path/rule/
		\cp -a -r /tmp/free_waf/rule/url.json $waf_path/rule/url.json
		\cp -a -r /tmp/free_waf/rule/args.json $waf_path/rule/args.json
		\cp -a -r /tmp/free_waf/rule/post.json $waf_path/rule/post.json
		\cp -a -r /tmp/free_waf/rule/cn.json $waf_path/rule/cn.json
		\cp -a -r /tmp/free_waf/rule/head_white.json $waf_path/rule/head_white.json
		\cp -a -r /tmp/free_waf/rule/ip_black.json $waf_path/rule/ip_black.json
		\cp -a -r /tmp/free_waf/rule/ip_white.json $waf_path/rule/ip_white.json
		\cp -a -r /tmp/free_waf/rule/scan_black.json $waf_path/rule/scan_black.json
		\cp -a -r /tmp/free_waf/rule/url_black.json $waf_path/rule/url_black.json
		\cp -a -r /tmp/free_waf/rule/url_white.json $waf_path/rule/url_white.json
		\cp -a -r /tmp/free_waf/rule/user_agent.json $waf_path/rule/user_agent.json
	fi
	\cp -a -r /tmp/free_waf/init.lua $waf_path/init.lua
	\cp -a -r /tmp/free_waf/waf.lua $waf_path/waf.lua
	
	if [ ! -f $waf_path/site.json ];then
		\cp -a -r /tmp/free_waf/site.json $waf_path/site.json
	fi
	
	if [ ! -f $waf_path/config.json ];then
		\cp -a -r /tmp/free_waf/config.json $waf_path/config.json
	fi
	
	if [ ! -f $waf_path/total.json ];then
		\cp -a -r /tmp/free_waf/total.json $waf_path/total.json
	fi
	
	if [ ! -f $waf_path/drop_ip.log ];then
		\cp -a -r /tmp/free_waf/drop_ip.log $waf_path/drop_ip.log
	fi
	chown www:www /www/server/free_waf/drop_ip.log
	chown www:www /www/server/free_waf/total.json
	chmod -R 755 /www/server/free_waf
	chmod -R 666 /www/server/free_waf/rule
	chmod -R 666 /www/server/free_waf/total.json
	chmod -R 666 /www/server/free_waf/drop_ip.log
	rm -rf /tmp/free_waf
	/etc/init.d/nginx reload
	echo 'The installation is complete' > $install_tmp
}

Install_cjson()
{
	if [ -f /usr/bin/yum ];then
		isInstall=`rpm -qa |grep lua-devel`
		if [ "$isInstall" == "" ];then
			yum install lua lua-devel -y
		fi
	else
		isInstall=`dpkg -l|grep liblua5.1-0-dev`
		if [ "$isInstall" == "" ];then
			apt-get install lua5.1 lua5.1-dev -y
		fi
	fi
	if [ ! -f /usr/local/lib/lua/5.1/cjson.so ];then
		wget -O lua-cjson-2.1.0.tar.gz $download_Url/install/src/lua-cjson-2.1.0.tar.gz -T 20
		tar xvf lua-cjson-2.1.0.tar.gz
		rm -f lua-cjson-2.1.0.tar.gz
		cd lua-cjson-2.1.0
		make clean
		make -B
		make install
		cd ..
		rm -rf lua-cjson-2.1.0
		ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so
		ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so
	else
		if [ -d "/usr/lib64/lua/5.1" ];then
			ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib64/lua/5.1/cjson.so
		fi
		
		if [ -d "/usr/lib/lua/5.1" ];then
			ln -sf /usr/local/lib/lua/5.1/cjson.so /usr/lib/lua/5.1/cjson.so
		fi
	fi
}

Uninstall_btwaf()
{
	rm -rf $pluginPath
	rm -rf $waf_path
	rm -rf /www/server/panel/vhost/nginx/free_waf.conf
	/etc/init.d/nginx reload
}

if [ "${1}" == 'install' ];then
	Install_btwaf
elif  [ "${1}" == 'update' ];then
	Install_btwaf
elif [ "${1}" == 'uninstall' ];then
	Uninstall_btwaf
fi



