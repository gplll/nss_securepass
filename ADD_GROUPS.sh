#!/bin/sh
spctl group add basket70s@wiran.net
spctl group xattrs basket70s@wiran.net set posixGid 1020
spctl group member add cjura@wiran.net basket70s@wiran.net
spctl group member add bmorse@wiran.net basket70s@wiran.net
spctl group member add dmeneghin@wiran.net basket70s@wiran.net
spctl group member add jgianelli@wiran.net basket70s@wiran.net

spctl user add -n larry -s bird -e larry.bird@wiran.net -m +00000000 lbird@wiran.net
spctl user xattrs lbird@wiran.net set posixuid 1010
spctl user xattrs lbird@wiran.net set posixgid 1015
spctl user add -n julius -s erving -e julius.erving@wiran.net -m +00000000 jerving@wiran.net
spctl user xattrs jerving@wiran.net set posixuid 1011
spctl user xattrs jerving@wiran.net set posixgid 1015
spctl user add -n michael -s jordan -e michael.jordan@wiran.net -m +00000000 mjordan@wiran.net
spctl user xattrs mjordan@wiran.net set posixuid 1012
spctl user xattrs mjordan@wiran.net set posixgid 1015

spctl group add nba@wiran.net
spctl group xattrs nba@wiran.net set posixGid 1021
spctl group member add lbird@wiran.net nba@wiran.net
spctl group member add jerving@wiran.net nba@wiran.net
spctl group member add mjordan@wiran.net nba@wiran.net

spctl group member list basket70s@wiran.net
spctl group member list nba@wiran.net

