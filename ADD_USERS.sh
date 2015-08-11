#!/bin/sh
sp-user-add -n john -s gianelli -e john.gianelli@wiran.net -m +00000000000 jgianelli@wiran.net
sp-user-xattrs jgianelli@wiran.net set posixuid 1001
sp-user-xattrs jgianelli@wiran.net set posixgid 101
sp-user-xattrs jgianelli@wiran.net set posixshell /bin/sh
sp-user-xattrs jgianelli@wiran.net set posixhomedir /usr/home
sp-user-xattrs jgianelli@wiran.net set posixgecos 'was a really good player'

sp-user-add -n bob -s morse -e bob.morse@wiran.net -m +00000000000 bmorse@wiran.net
sp-user-xattrs bmorse@wiran.net set posixuid 1002
sp-user-xattrs bmorse@wiran.net set posixgid 102
sp-user-xattrs bmorse@wiran.net set posixshell /bin/bash
sp-user-xattrs bmorse@wiran.net set posixhomedir /home
sp-user-xattrs bmorse@wiran.net set posixgecos 'one of my models'

sp-user-add -n chuck -s jura -e chuck.jura@wiran.net -m +00000000000 cjura@wiran.net
sp-user-xattrs cjura@wiran.net set posixuid 1003
sp-user-xattrs cjura@wiran.net set posixgid 103
sp-user-xattrs cjura@wiran.net set posixshell /bin/bash
sp-user-xattrs cjura@wiran.net set posixhomedir /home
sp-user-xattrs cjura@wiran.net set posixgecos 'great center'

sp-user-add -n charlie -s yelverton -e charlie.yelverton@wiran.net -m +00000000000 cyelverton@wiran.net
sp-user-xattrs cyelverton@wiran.net set posixuid 1004
sp-user-xattrs cyelverton@wiran.net set posixgid 104
sp-user-xattrs cyelverton@wiran.net set posixshell /bin/bash
sp-user-xattrs cyelverton@wiran.net set posixhomedir /home
sp-user-xattrs cyelverton@wiran.net set posixgecos 'best defender'

sp-user-add -n dino -s meneghin -e dino.meneghin@wiran.net -m +00000000000 dmeneghin@wiran.net
sp-user-xattrs dmeneghin@wiran.net set posixuid 1005
sp-user-xattrs dmeneghin@wiran.net set posixgid 105
sp-user-xattrs dmeneghin@wiran.net set posixshell /bin/bash
sp-user-xattrs dmeneghin@wiran.net set posixhomedir /home
sp-user-xattrs dmeneghin@wiran.net set posixgecos 'il monumento nazionale'

sp-user-add -n pierluigi -s marzorati -e pierluigi.marzorati@wiran.net -m +00000000000 pmarzorati@wiran.net
sp-user-xattrs pmarzorati@wiran.net set posixuid 1006
sp-user-xattrs pmarzorati@wiran.net set posixgid 106
sp-user-xattrs pmarzorati@wiran.net set posixshell /bin/bash
sp-user-xattrs pmarzorati@wiran.net set posixhomedir /home
sp-user-xattrs pmarzorati@wiran.net set posixgecos 'il giocatore ingegnere'
