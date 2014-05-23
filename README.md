## Overview

rb_snmp_pass.rb is a script written in ruby to work like a snmp 
agent using the clause 'pass_persist' from net-snmp and serves 
snort statistics provided via perfmonitor preprocessor.

You can find more information about net-snmp and snort at his official homepage:

http://www.net-snmp.org

http://www.snort.org

With rb_snmp_pass.rb and its MIB file, a system running snort can provides
all statistics defined in the MIB file and extra information if ipmitool
is installed.

