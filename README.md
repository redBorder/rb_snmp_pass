## Overview

rb_snmp_pass.rb is a script written in ruby to work like a snmp 
agent using the clause 'pass_persist' from net-snmp and serves 
snort statistics provided via perfmonitor preprocessor.

You can find more information about [net-snmp](http://www.net-snmp.org/) and 
[snort](http://www.snort.org) at his official homepage.

With rb_snmp_pass.rb and its MIB file, a system running snort can provides
all statistics defined in the MIB file and extra information if ipmitool
is installed.

