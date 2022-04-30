#!/bin/bash

pyv=${1}
vpath=${2}
py_path=/www/server/python_manager/versions
mkdir -p ${py_path}
install_python()
{
  wget -O /tmp/Python-${pyv}.tar.xz http://node.aapanel.com/src/Python-${pyv}.tar.xz
  cd /tmp/ && xz -d /tmp/Python-${pyv}.tar.xz && tar -xvf /tmp/Python-${pyv}.tar && cd /tmp/Python-${pyv}
  ./configure --prefix=${py_path}/${pyv}
  make && make install
  rm -rf /tmp/Python-*
}

install_pip()
{
  cd ${vpath}
  wget -O get-pip.py http://node.aapanel.com/install/plugin/pythonmamager/pip/get-pip${pyv:0:3}.py
  if [ -f ${vpath}/bin/python ];then
    bin/python get-pip.py
  else
    bin/python3 get-pip.py
  fi
}

if [ "$vpath" == "" ];then
  install_python
else
  install_pip
fi


