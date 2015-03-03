#!/bin/bash

apt-get update
apt-get install -y xinetd

mkdir /tmp/rop
cp -r /vagrant/* /tmp/rop

# make vulnuser
mkdir /home/vulnuser
useradd -d /home/vulnuser vulnuser
chown -R vulnuser:vulnuser /home/vulnuser
chmod 700 /home/vulnuser

# configure vulnuser and flag
/tmp/rop/generate/generate.py easy
cp vuln /home/vulnuser/
echo "flag{congrats, this should be randomly generated in the future}" > /home/vulnuser/flag
chown root:vulnuser /home/vulnuser/flag
chmod 640 /home/vulnuser/flag

# remove the C file
rm out.c

# place xinetd config files
cp /tmp/rop/config/vuln.xinetd /etc/xinetd.d/vuln

# drop the exploit skeleton into the home directory 
cp /tmp/rop/skeletons/pwn-easy.py /home/vagrant/

# copy libc into the directory for beginners
cp /lib/i386-linux-gnu/libc.so.6 .

# remove the build scripts
rm -rf /tmp/rop

# restart xinetd to get the service running
service xinetd restart
