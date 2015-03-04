#!/bin/bash

# make vulnuser
mkdir /home/vulnuser
useradd -d /home/vulnuser vulnuser
chown -R root:vulnuser /home/vulnuser
chmod 750 /home/vulnuser

# configure vulnuser and flag
cd /tmp/challenge-files
/tmp/challenge-files/generate/generate.py easy

# configure the vulnerable binary
cp /tmp/challenge-files/vuln /home/vulnuser/
chown root:vulnuser /home/vulnuser/vuln
chmod 750 /home/vulnuser/vuln

# configure the flag
echo "flag{congrats, this should be randomly generated in the future}" > /home/vulnuser/flag
chown root:vulnuser /home/vulnuser/flag
chmod 640 /home/vulnuser/flag

# place xinetd config files
cp /tmp/challenge-files/config/vuln.xinetd /etc/xinetd.d/vuln

# drop the vulnerable binary into the user's directory
cp /tmp/challenge-files/vuln /home/student

# drop the exploit skeleton into the home directory 
cp /tmp/challenge-files/skeletons/pwn-easy.py /home/student/

# copy libc into the directory for beginners
cp /lib/i386-linux-gnu/libc.so.6 .

# remove the build scripts
rm -rf /tmp/challenge-files

# restart xinetd to get the service running
service xinetd restart
