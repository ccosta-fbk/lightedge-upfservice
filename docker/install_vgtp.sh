#!/bin/bash

git clone https://$1:$2@github.com/rriggio/upflib /upflib
git clone https://github.com/lightedge/lightedge-upfservice /lightedge-upfservice

cd /upflib
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/tmp/build
make
make install

cd /lightedge-upfservice
./configure --with-click=/usr/local --with-upflib=/tmp/build
make
make install

rm -r /tmp/build
rm -r /upflib
rm -r /lightedge-upfservice
