## Overview

rb_snmp_pass.rb is a script written in ruby to work like a snmp 
agent using the clause 'pass_persist' from net-snmp and serves 
snort statistics provided via perfmonitor preprocessor.

You can find more information about [net-snmp](http://www.net-snmp.org/) and 
[snort](http://www.snort.org) at his official homepage.

With rb_snmp_pass.rb and its MIB file, a system running snort can provides
all statistics defined in the MIB file and extra information if ipmitool
is installed.

## Changes

- 14/05/2014 - Version 0.1 - Uploaded to github first version
- 23/05/2014 - Version 0.2 - New version with multi groups support (2 index)

## Install

First, install ruby and needed gems. To install ruby, you can follow instruction 
from [Ruby Version Manager](https://rvm.io/). You will need the gems: yaml, syslog.

Copy the script rb_snmp_pass.rb to your favorite bin location, for example
'/usr/local/bin', and change permissions:

```
# chmod 755 /usr/local/bin/rb_snmp_pass.rb
```

Edit your snmpd.conf file from net-snmpd package and include the following line:

pass_persist .1.3.6.1.4.1.39483 /usr/local/bin/rb_snmp_pass.rb

Copy or create the config file for the script:

```
# cp rb_snmp_pass.yml /etc/rb_snmp_pass.yml
# vim /etc/rb_snmp_pass.yml
...
```

Copy the MIB file to the mibs directory and restart snmpd service. For example, 
in a CentOS distribution:

```
# cp REDBORDER-MIB.txt /usr/share/snmp/mibs/
# service snmpd restart
```

If you have configured correctly the yaml file and you have snort running 
with proper configuration (see bellow), then you can execute a snmpwalk over
the agent, for example, with version 1 and community public:

```
# snmpwalk -v1 -c public 127.0.0.1 REDBORDER-MIB::redborder.ips
REDBORDER-MIB::instancesGroupName.1.1 = STRING: "default"
REDBORDER-MIB::instancesGroupName.1.2 = STRING: "default"
REDBORDER-MIB::instancesGroupName.1.3 = STRING: "default"
REDBORDER-MIB::instancesGroupName.1.4 = STRING: "default"
REDBORDER-MIB::instancesGroupID.1.1 = INTEGER: 0
REDBORDER-MIB::instancesGroupID.1.2 = INTEGER: 0
REDBORDER-MIB::instancesGroupID.1.3 = INTEGER: 0
REDBORDER-MIB::instancesGroupID.1.4 = INTEGER: 0
...
REDBORDER-MIB::alertsPerSecond.1.1 = INTEGER: 33 (1/1000) alerts/s
REDBORDER-MIB::alertsPerSecond.1.2 = INTEGER: 40 (1/1000) alerts/s
REDBORDER-MIB::alertsPerSecond.1.3 = INTEGER: 22 (1/1000) alerts/s
REDBORDER-MIB::alertsPerSecond.1.4 = INTEGER: 200 (1/1000) alerts/s
...
REDBORDER-MIB::avgBytesPerPacket.1.1 = INTEGER: 448000 (1/1000) bytes/pkt
REDBORDER-MIB::avgBytesPerPacket.1.2 = INTEGER: 557000 (1/1000) bytes/pkt
REDBORDER-MIB::avgBytesPerPacket.1.3 = INTEGER: 344000 (1/1000) bytes/pkt
REDBORDER-MIB::avgBytesPerPacket.1.4 = INTEGER: 1016000 (1/1000) bytes/pkt
... 
```

