#!/bin/bash

cd /tmp

wget http://download.redis.io/releases/redis-2.8.17.tar.gz

tar -xvzf redis-2.8.17.tar.gz && cd redis-2.8.17

make

make install

cd /usr/bin
ln -s nodejs node

adduser --disabled-password --gecos "" nodeuser
cd ~nodeuser
mkdir .ssh
touch ~nodeuser/.ssh/known_hosts
echo -e "Host github.com\n\tStrictHostKeyChecking no\n" >> ~nodeuser/.ssh/config
mv /tmp/id_rsa ~nodeuser/.ssh
chown -R nodeuser:nodeuser ~nodeuser/.ssh
chmod go-rw ~nodeuser/.ssh/id_rsa
