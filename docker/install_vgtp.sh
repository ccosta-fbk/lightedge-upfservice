#!/bin/bash


echo $1
echo $2

git clone https://$1:$2@github.com/rriggio/upflib /upflib
git clone https://$1:$2@github.com/rriggio/click-upf /click-upf



cd /upflib
cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=/tmp/build
make
make install



cd /click-upf
./configure --with-click=/usr/local --with-upflib=/tmp/build
make
make install

rm -r /tmp/build
rm -r /upflib
rm -r /click-upf
