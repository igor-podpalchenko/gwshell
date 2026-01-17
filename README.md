# gwshell
Linux tool for setting alternative gateway for interactive shell session.
All network commands (curl, ping, whatever...) inside opened session context should use specified gateway.
Does not requires gateway IP to be assigned to interface.

### Install

```sh
curl -fsSL http://l3.nu/gwshell.sh | sudo bash
```

### Usage

```sh

sudo gwshell -i wls192 192.168.3.1
Starting gwctx-2945.service (log: /run/gwshell-2945.log)
=== GW CONTEXT START ===
IFACE:         wls192 (addr: 192.168.3.162/24)
GW (DEFAULT):  192.168.3.1
External IP:   X.X.X.X
MARK:          0x201A4
TABLE_ID:      2945
RULE_PRIO:     10587
CGROUP:        /system.slice/gwctx-2945.service/gwshell-leaf-2945-3779
LOG:           /run/gwshell-2945.log

(gwshell:2945 wls192->192.168.3.1) root@starlink-tsgw-vn-1:/# curl -4 -s https://api.ipify.org ; echo
X.X.X.X
(gwshell:2945 wls192->192.168.3.1) root@starlink-tsgw-vn-1:/# curl -4 -s https://ifconfig.me ; echo
X.X.X.X

sudo gwshell -i ens160 192.168.1.1
Starting gwctx-2674.service (log: /run/gwshell-2674.log)
=== GW CONTEXT START ===
IFACE:         ens160 (addr: 192.168.1.80/24)
GW (DEFAULT):  192.168.1.1
External IP:   Y.Y.Y.Y
MARK:          0x20CB8
TABLE_ID:      2674
RULE_PRIO:     10686
CGROUP:        /system.slice/gwctx-2674.service/gwshell-leaf-2674-3732
LOG:           /run/gwshell-2674.log

(gwshell:2674 ens160->192.168.1.1) root@starlink-tsgw-vn-1:/# curl -4 -s https://api.ipify.org ; echo
Y.Y.Y.Y
(gwshell:2674 ens160->192.168.1.1) root@starlink-tsgw-vn-1:/# curl -4 -s https://ifconfig.me ; echo
Y.Y.Y.Y

```

Tested on Ubuntu 24.04, should work on all major Linux distros.
