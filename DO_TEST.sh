#!/bin/sh
set +v
echo
./sp_client -l
echo
getent passwd
echo
getent passwd 1000
getent passwd 1001
getent passwd 1002
getent passwd 1003
getent passwd 1004
getent passwd 1005
getent passwd 1006
