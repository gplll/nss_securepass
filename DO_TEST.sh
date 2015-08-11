#!/bin/sh
#set -v
echo
#./sp_client -l
echo
getent passwd
echo
#getent passwd 1000
#getent passwd 1001
#getent passwd 1002
#getent passwd 1003
#getent passwd 1004
#getent passwd 1005
#getent passwd 1006
echo
if [ $# != 2 ]
then
	echo "if you want to check authentication and pwd change, pls. run: $0 OTP Password"
else
	echo
	set -v
	./sp_client -w "gp@wiran.net $2"
	echo
	./sp_client -t "gp@wiran.net $1$2"
	echo
	./pam_client -p gp
	echo
	./pam_client -a gp
fi
