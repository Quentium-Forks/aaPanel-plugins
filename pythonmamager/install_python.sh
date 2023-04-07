#!/bin/bash

pyv=${1}
vpath=${2}
py_path=/www/server/python_manager/versions
mkdir -p ${py_path}
install_python()
{
  wget -O /tmp/Python-${pyv}.tar.xz https://www.python.org/ftp/python/${pyv}/Python-${pyv}.tar.xz
  cd /tmp/ && xz -d /tmp/Python-${pyv}.tar.xz && tar -xvf /tmp/Python-${pyv}.tar && cd /tmp/Python-${pyv}
  ./configure --prefix=${py_path}/${pyv}
  make && make install
  rm -rf /tmp/Python-*
}

install_pip()
{
  cd ${vpath}
  wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py
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
