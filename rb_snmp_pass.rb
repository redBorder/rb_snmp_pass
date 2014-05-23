#!/usr/bin/ruby
# Copyright (C) 2014 Eneo Tecnologia S.L.
# Author: Juan J. Prieto <jjprieto@eneotecnologia.com>, <jjprieto@redborder.net>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2 as
# published by the Free Software Foundation.  You may not use, modify or
# distribute this program under any other version of the GNU General
# Public License V2.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.

# The OID table looks like:
#
#         1                  2                 3                   4              5              6                7                    8                  9                10         11...
# instancesGroupIndex | instanceIndex | instanceGroupName | instanceGroupID | instanceID | procStatState | procStatTimestamp | procStatTimesticks | pktDropPercent | alertPerSecond |  ...  
# --------------------+---------------+-------------------+-----------------+------------+---------------+-------------------+--------------------+----------------+----------------+-------
#         1           |      1        |      "default"    |        0        |      0     |       1       |    1396511411     |        300         |      20        |       4        |  ...
# --------------------+---------------+-------------------+-----------------+------------+---------------+-------------------+--------------------+----------------+----------------+-------
#        ...          |     ...       |         ...       |       ...       |     ...    |      ...      |       ...         |        ...         |      ...       |      ...       |
#         1           |      8        |      "default"    |        0        |      7     |       1       |    1396511580     |        215         |       0        |       5        |  ...
# --------------------+---------------+-------------------+-----------------+------------+---------------+-------------------+--------------------+----------------+----------------+-------
#         2           |      1        |       "dmz"       |        3        |      0     |       1       |    1396511480     |        290         |      15        |       7        |  ...
# --------------------+---------------+-------------------+-----------------+------------+---------------+-------------------+--------------------+----------------+----------------+-------
#        ...          |     ...       |         ...       |       ...       |     ...    |      ...      |       ...         |        ...         |      ...       |      ...       |

# params: time, wire_mbits_per_sec.realtime, pkt_drop_percent, kpackets_wire_per_sec.realtime, total_sessions, idle[x], alerts_per_minute

require 'yaml'
require 'syslog'

MIBFILE = "/usr/share/snmp/mibs/REDBORDER-MIB.txt"
CONFFILE = "/etc/rb_snmp_pass.yml"

if File.file?(CONFFILE)
    $statConfHash = YAML.load(File.open(CONFFILE))
else
    puts "Error: #{CONFFILE} file not found"
    exit(1)
end

if $statConfHash[:versionPlatform].nil?
    # version 3 by default
    $statConfHash[:versionPlatform] = 3
end
if $statConfHash[:statTimestampInterval].nil?
    # interval of 300 seconds by default
    $statConfHash[:statTimestampInterval] = 300
end

# iso(1).org(3).dod(6).internet(1).private(4).enterprise(1).redborder(39483)
BASEOID = ".1.3.6.1.4.1.39483"

$statParams = Hash.new
$statParamsIndex = Hash.new
$numSequence = 10 # default value

if File.file?(MIBFILE)
    mibFile = IO.readlines(MIBFILE)
    mibFile.each do |x|
        m = /StatValue (?<id>\d+), (?<mibStat>[^\s]+) => (?<snortStat>[^\s]+)/.match(x)
        if m
            # ID: m[:id], mibStat: m[:mibStat], snortStat: m[:snortStat]
            # statParams: id => stats_names
            # statParamsIndex: stats_names => id
            $statParams["#{m[:id]}"] = { :mibStat => "#{m[:mibStat]}", :snortStat => "#{m[:snortStat]}" }
            $statParamsIndex["#{m[:mibStat]}"] = "#{m[:id]}"
            $statParamsIndex["#{m[:snortStat]}"] = "#{m[:id]}"
            $numSequence = m[:id].to_i # last value always
        end
    end
else
    puts "Error: #{MIBFILE} file not found"
    exit(1)
end

def log(message)
    Syslog.open("rb_snmp_pass", Syslog::LOG_PID | Syslog::LOG_CONS) { |s| s.warning message }
end

def answer(message)
    puts "#{message}"
    $stdout.flush
end

def is_oid_correct(oid)
    if /^#{BASEOID}(\.\d+)+$/.match(oid)
        if /^#{BASEOID}\.2\.2(\.1(\.1(\.\d+(\.\d+(\.\d+)?)?)?)?)?$/.match(oid)
            # table of stats from snort
            m = /^#{BASEOID}(\.2(\.2(\.1(\.1(\.(?<sequence>\d+)(\.(?<instancesGroupIndex>\d+)(\.(?<instanceIndex>\d+))?)?)?)?)?)?)?$/.match(oid)
            if m[:sequence].nil?
                true
            else
                if (2..$numSequence).include? m[:sequence].to_i
                    if m[:instancesGroupIndex].nil?
                        true
                    else
                        if (1..$statConfHash[:instancesGroup].count).include? m[:instancesGroupIndex].to_i
                            if m[:instanceIndex].nil?
                                true
                            else
                                if (1..$statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:instances].count).include? m[:instanceIndex].to_i
                                    true
                                else
                                    false
                                end
                            end
                        else
                            false
                        end
                    end
                else
                    false
                end
            end
        elsif /^#{BASEOID}\.2\.1(\.(1|2)(\.0)?)?$/.match(oid)
            # scalars from manufacturer
            m = /^#{BASEOID}(\.2(\.1(\.(?<id>\d+)(\.0)?)?)?)?$/.match(oid)
            if m[:id].nil?
                true
            else
                if (1..2).include? m[:id].to_i
                    true
                else
                    false
                end
            end
        elsif /^#{BASEOID}\.2\.1(\.3(\.1(\.\d+(\.\d+)?)?)?)?$/.match(oid) and $statConfHash[:tempSensors]
            # temperature sensors
            m = /^#{BASEOID}\.2\.1(\.3(\.1(\.(?<sequence>\d+)(\.(?<tempIndex>\d+))?)?)?)?$/.match(oid)
            if m[:sequence].nil?
                true
            else
                if (2..3).include? m[:sequence].to_i
                    if m[:tempIndex].nil?
                        true
                    else
                        if (1..$statConfHash[:tempSensors].count).include? m[:tempIndex].to_i
                            true
                        else
                            false
                        end
                    end
                else
                    false
                end
            end
        elsif /^#{BASEOID}\.2\.1(\.4(\.1(\.\d+(\.\d+)?)?)?)?$/.match(oid) and $statConfHash[:fanSensors]
            # FAN sensors
            m = /^#{BASEOID}\.2\.1(\.4(\.1(\.(?<sequence>\d+)(\.(?<fanIndex>\d+))?)?)?)?$/.match(oid)
            if m[:sequence].nil?
                true
            else
                if (2..3).include? m[:sequence].to_i
                    if m[:fanIndex].nil?
                        true
                    else
                        if (1..$statConfHash[:fanSensors].count).include? m[:fanIndex].to_i
                            true
                        else
                            false
                        end
                    end
                else
                    false
                end
            end
        elsif /^#{BASEOID}(\.\d+)?$/.match(oid)
            m = /^#{BASEOID}(\.(?<id>\d+))?$/.match(oid)
            if m[:id].nil?
                # iso(1).org(3).dod(6).internet(1).private(4).enterprise(1).redborder(39483)
                true
            elsif m[:id].to_i == 2
                # iso(1).org(3).dod(6).internet(1).private(4).enterprise(1).redborder(39483).ips(2)
                true
            else
                false
            end
        else
            false
        end
    else
        false
    end
end

def is_fulloid_correct(oid)
    if /^#{BASEOID}\.2\.2\.1\.1\.\d+\.\d+\.\d+$/.match(oid)
        # table of stats from snort
        m = /^#{BASEOID}\.2\.2\.1\.1\.(?<sequence>\d+)\.(?<instancesGroupIndex>\d+)\.(?<instanceIndex>\d+)$/.match(oid)
        if m[:sequence].nil? or m[:instancesGroupIndex].nil? or m[:instanceIndex].nil?
            false
        else
            if m and ((2..$numSequence).include? m[:sequence].to_i) and ((1..$statConfHash[:instancesGroup].count).include? m[:instancesGroupIndex].to_i) and ((1..$statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:instances].count).include? m[:instanceIndex].to_i)
                true
            else
                false
            end
        end
    elsif /^#{BASEOID}\.2\.1\.(1|2)\.0$/.match(oid)
        # scalars from manufacturer
        m = /^#{BASEOID}\.2\.1\.(?<id>\d+)\.0$/.match(oid)
        if m[:id].nil?
            false
        else
            if (1..2).include? m[:id].to_i
                true
            else
                false
            end
        end
    elsif /^#{BASEOID}\.2\.1\.3\.1\.\d+\.\d+$/.match(oid) and $statConfHash[:tempSensors]
        # table of temperature 
        m = /^#{BASEOID}\.2\.1\.3\.1\.(?<sequence>\d+)\.(?<tempIndex>\d+)$/.match(oid)
        if m[:sequence].nil? or m[:tempIndex].nil?
            false
        else
            if m and ((2..3).include? m[:sequence].to_i) and ((1..$statConfHash[:tempSensors].count).include? m[:tempIndex].to_i)
                true
            else
                false
            end
        end
    elsif /^#{BASEOID}\.2\.1\.4\.1\.\d+\.\d+$/.match(oid) and $statConfHash[:fanSensors]
        # table of FAN
        m = /^#{BASEOID}\.2\.1\.4\.1\.(?<sequence>\d+)\.(?<fanIndex>\d+)$/.match(oid)
        if m[:sequence].nil? or m[:fanIndex].nil?
            false
        else
            if m and ((2..3).include? m[:sequence].to_i) and ((1..$statConfHash[:fanSensors].count).include? m[:fanIndex].to_i)
                true
            else
                false
            end
        end
    else
        false
    end
end

def get_next_oid(oid)
    if /^#{BASEOID}(\.\d+)?$/.match(oid)
        m = /^#{BASEOID}(\.(?<id>\d+))?$/.match(oid)
        if m[:id].nil?
            return "#{BASEOID}.2.1.1.0"
        elsif m[:id].to_i == 2
            return "#{BASEOID}.2.1.1.0"
        else
            return "NONE"
        end
    elsif /^#{BASEOID}(\.2(\.1(\.(1|2)(\.\d+)?)?)?)?$/.match(oid)
        # scalars form manufacturer
        m = /^#{BASEOID}(\.2(\.1(\.(?<id>\d+)(\.(?<zero>\d+))?)?)?)?$/.match(oid)
        if m[:id].nil? or (m[:id].to_i == 1 and m[:zero].nil?)
            return "#{BASEOID}.2.1.1.0"
        elsif m[:id].to_i == 1 and m[:zero].to_i == 0
            return "#{BASEOID}.2.1.2.0"
        elsif m[:id].to_i == 2 and m[:zero].nil?
            return "#{BASEOID}.2.1.2.0"
        elsif m[:id].to_i == 2 and m[:zero].to_i == 0
            if $statConfHash[:tempSensors]
                return "#{BASEOID}.2.1.3.1.2.1"
            elsif $statConfHash[:fanSensors]
                return "#{BASEOID}.2.1.4.1.2.1"
            else
                return "#{BASEOID}.2.2.1.1.3.1.1"
            end
        else
            return "NONE"
        end
    elsif /^#{BASEOID}(\.2(\.1(\.3(\.1(\.\d+(\.\d+)?)?)?)?)?)?$/.match(oid) and $statConfHash[:tempSensors]
        # table of temperature
        m = /^#{BASEOID}(\.2(\.1(\.3(\.1(\.(?<sequence>\d+)(\.(?<tempIndex>\d+))?)?)?)?)?)?$/.match(oid)
        if m[:sequence].nil? and m[:tempIndex].nil?
            return "#{BASEOID}.2.1.3.1.2.1"
        elsif m[:tempIndex].nil?
            return "#{BASEOID}.2.1.3.1.#{m[:sequence]}.1"
        else
            # return next of "#{BASEOID}.2.1.3.1.x.y"
            x = m[:sequence].to_i
            y = m[:tempIndex].to_i
            if (y+1) <= $statConfHash[:tempSensors].count
                return "#{BASEOID}.2.1.3.1.#{x}.#{y+1}"
            elsif (x+1) <= 3
                return "#{BASEOID}.2.1.3.1.#{x+1}.1"
            else
                if $statConfHash[:fanSensors]
                    return "#{BASEOID}.2.1.4.1.2.1"
                else
                    return "#{BASEOID}.2.2.1.1.3.1.1"
                end
            end
        end
    elsif /^#{BASEOID}(\.2(\.1(\.4(\.1(\.\d+(\.\d+)?)?)?)?)?)?$/.match(oid) and $statConfHash[:fanSensors]
        # table of fan
        m = /^#{BASEOID}(\.2(\.1(\.4(\.1(\.(?<sequence>\d+)(\.(?<fanIndex>\d+))?)?)?)?)?)?$/.match(oid)
        if m[:sequence].nil? and m[:fanIndex].nil?
            return "#{BASEOID}.2.1.4.1.2.1"
        elsif m[:fanIndex].nil?
            return "#{BASEOID}.2.1.4.1.#{m[:sequence]}.1"
        else
            # return next of "#{BASEOID}.2.1.4.1.x.y"
            x = m[:sequence].to_i
            y = m[:fanIndex].to_i
            if (y+1) <= $statConfHash[:fanSensors].count
                return "#{BASEOID}.2.1.4.1.#{x}.#{y+1}"
            elsif (x+1) <= 3
                return "#{BASEOID}.2.1.4.1.#{x+1}.1"
            else
                return "#{BASEOID}.2.2.1.1.3.1.1"
            end
        end
    elsif /^#{BASEOID}(\.2(\.2(\.1(\.1(\.\d+(\.\d+(\.\d+)?)?)?)?)?)?)?$/.match(oid)
        m = /^#{BASEOID}(\.2(\.2(\.1(\.1(\.((?<sequence>\d+)(\.(?<instancesGroupIndex>\d+(\.(?<instanceIndex>\d+))?))?)?)?)?)?)?)?$/.match(oid)
        if m[:sequence].nil? and m[:instancesGroupIndex].nil? and m[:instanceIndex].nil?
            return "#{BASEOID}.2.2.1.1.3.1.1"
        elsif m[:instancesGroupIndex].nil? and m[:instanceIndex].nil?
            # return "#{BASEOID}.2.1.1.1.x.1.1"
            return "#{BASEOID}.2.2.1.1.#{m[:sequence]}.1.1"
        elsif m[:instanceIndex].nil?
            # return "#{BASEOID}.2.1.1.1.x.y.1"
            return "#{BASEOID}.2.2.1.1.#{m[:sequence]}.#{m[:instancesGroupIndex]}.1"
        else
            # return next of "#{BASEOID}.2.2.1.1.x.y.z"
            x = m[:sequence].to_i
            y = m[:instancesGroupIndex].to_i
            z = m[:instanceIndex].to_i
            if (z+1) <= $statConfHash[:instancesGroup][y-1][:instances].count
                return "#{BASEOID}.2.2.1.1.#{x}.#{y}.#{z+1}"
            elsif (y+1) <= $statConfHash[:instancesGroup].count
                return "#{BASEOID}.2.2.1.1.#{x}.#{y+1}.1"
            elsif (x+1) <= $numSequence
                return "#{BASEOID}.2.2.1.1.#{x+1}.1.1"
            else
                return "NONE"
            end
        end
    else
        return "NONE"
    end
end

def read_stats_from_file(h)
    # calculate stats values for a group and instance
    if $statConfHash[:statFile].nil?
        if $statConfHash[:versionPlatform] == 2
            statFile = "/var/log/snort/instance-#{h[:instance]}/stats/snort.stats"
        else # version 3
            statFile = "/var/log/snort/#{h[:group]}/instance-#{h[:instance]}/stats/snort.stats"
        end
    else
        statFile = $statConfHash[:statFile]
    end
    if File.file?(statFile)
        statHash = Hash.new
        statFile = IO.readlines(statFile)
        statTimestamp = statFile.last.chomp.split(",").first
        value = nil
        statFile[1].gsub(/^#/,"").chomp.split(",").each_with_index do |key,i|
            value = statFile.last.chomp.split(",")[i]
            statHash[key] = value
        end
        return statHash[h[:statname]]
    else
        return nil
    end
end

def get_oid_response(oid)
    output = ""
    if /^#{BASEOID}\.2\.2\.1\.1\.\d+\.\d+\.\d+$/.match(oid)
        # Snort statistics
        m = /^#{BASEOID}\.2\.2\.1\.1\.(?<sequence>\d+)\.(?<instancesGroupIndex>\d+)\.(?<instanceIndex>\d+)$/.match(oid)
        if m[:sequence].to_i == 3
            # send instanceGroupName
            answer(oid)
            answer("string")
            answer("#{$statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:name]}")
        elsif m[:sequence].to_i == 4
            # send instanceGroupID
            answer(oid)
            answer("integer")
            answer("#{$statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:group]}")
        elsif m[:sequence].to_i == 5
            # send instanceID
            answer(oid)
            answer("integer")
            answer("#{m[:instanceIndex].to_i-1}")
        elsif m[:sequence].to_i == 6
            # send state of statistic
            instance = m[:instanceIndex].to_i-1
            group = $statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:group]
            output = read_stats_from_file({:group => group, :instance => instance, :statname => "time"})
            answer(oid)
            answer("integer")
            if /^([\d\.]*)+$/.match(output)
                if (Time.now.to_i - output.to_i) <= $statConfHash[:statTimestampInterval].to_i
                    answer("1")
                else
                    answer("0")
                end
            else
                answer("0")
            end
        elsif m[:sequence].to_i == 7
            # send Timestamp from last statistic
            instance = m[:instanceIndex].to_i-1
            group = $statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:group]
            output = read_stats_from_file({:group => group, :instance => instance, :statname => "time"})
            answer(oid)
            answer("integer")
            if /^([\d\.]*)+$/.match(output)
                answer("#{output}")
            else
                # error reading time from stats?
                answer("0")
            end
        elsif m[:sequence].to_i == 8
            # send Timeticks from last statistic
            instance = m[:instanceIndex].to_i-1
            group = $statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:group]
            output = read_stats_from_file({:group => group, :instance => instance, :statname => "time"})
            answer(oid)
            answer("timeticks")
            if /^([\d\.]*)+$/.match(output)
                answer("#{(Time.now.to_i - output.to_i) * 100}")
            else
                # error reading time from stats?
                answer("0")
            end
        elsif (m[:sequence].to_i >= 9) && (m[:sequence].to_i < (9+$statParams.count))
            # send stat value
            instance = m[:instanceIndex].to_i-1
            group = $statConfHash[:instancesGroup][m[:instancesGroupIndex].to_i-1][:group]
            if $statParams["#{m[:sequence]}"][:snortStat] == "cpu_usage_percent"
                # in 2.2.28, instance = #cpu !!! ... in horama (3.x) #cpu is always 0
                output = read_stats_from_file({:group => group, :instance => instance, :statname => "idle[0]"})
                output = "#{(100 - output.to_f).round(3)}"
            elsif $statParams["#{m[:sequence]}"][:snortStat] == "syns_synacks_ratio"
                output_syns = read_stats_from_file({:group => group, :instance => instance, :statname => "syns_per_second"})
                output_synacks = read_stats_from_file({:group => group, :instance => instance, :statname => "synacks_per_second"})
                output = "#{(output_syns.to_f / output_synacks.to_f).round(3)}"
            elsif $statParams["#{m[:sequence]}"][:snortStat] == "alerts_per_minute"
                output = read_stats_from_file({:group => group, :instance => instance, :statname => "alerts_per_second"})
                output = "#{(output.to_f*60).round(3)}"
            else
                output = read_stats_from_file({:group => group, :instance => instance, :statname => $statParams["#{m[:sequence]}"][:snortStat]})
            end
            answer(oid)
            answer("integer")
            if /^([\d\.]*)+$/.match(output)
                outputnum = output.to_f * 1000
                answer("#{outputnum.to_i}")
            else
                # error reading from stats?
                answer("0")
            end
        else
            # oid is NONE or is not known
            answer("NONE")
        end
    elsif /^#{BASEOID}\.2\.1\.3\.1\.\d+\.\d+$/.match(oid) and $statConfHash[:tempSensors]
        # request temperature table
        m = /^#{BASEOID}\.2\.1\.3\.1\.(?<sequence>\d+)\.(?<tempIndex>\d+)$/.match(oid)
        if m[:sequence].to_i == 2
            # send tempSensorName
            answer(oid)
            answer("string")
            output = $statConfHash[:tempSensors][m[:tempIndex].to_i-1][:name]
            answer(output)
        elsif m[:sequence].to_i == 3
            # send tempSensorValue
            answer(oid)
            answer("integer")
            output = `#{$statConfHash[:tempSensors][m[:tempIndex].to_i-1][:script]}`.chomp
            if /^([\d\.]*)+$/.match(output)
                answer(output)
            else
                answer("0")
            end
        else
            answer("NONE")
        end
    elsif /^#{BASEOID}\.2\.1\.4\.1\.\d+\.\d+$/.match(oid)
        # request FAN table
        m = /^#{BASEOID}\.2\.1\.4\.1\.(?<sequence>\d+)\.(?<fanIndex>\d+)$/.match(oid)
        if m[:sequence].to_i == 2
            # send fanSensorName
            answer(oid)
            answer("string")
            if (1..5).include? m[:fanIndex].to_i
                answer("FAN#{m[:fanIndex]}")
            else
                answer("Unknown")
            end
        elsif m[:sequence].to_i == 3
            # send tempSensorValue
            answer(oid)
            answer("integer")
            if (1..4).include? m[:fanIndex].to_i
                output = `/opt/rb/bin/rb_get_sensor.sh -t Fan -s 'FAN[ ]*#{m[:fanIndex]}'`.chomp
            elsif m[:fanIndex].to_i == 5
                output = `/opt/rb/bin/rb_get_sensor.sh -t Fan -s 'FAN[ ]*[5|A]'`.chomp
            else
                output = "0"
            end
            answer(output)
        else
            answer("NONE")
        end
    elsif /^#{BASEOID}\.2\.1\.\d+\.0$/.match(oid)
        # request from manufacturer
        m = /^#{BASEOID}\.2\.1\.(?<id>\d+)\.0$/.match(oid)
        if m[:id].to_i == 1
            # request manufacturer name
            output = `dmidecode -t 1 | grep "Manufacturer:" | sed 's/[^:]*:[ ]*//'`.chomp
            answer(oid)
            answer("string")
            answer(output)
        elsif m[:id].to_i == 2
            # request product name
            output = `dmidecode -t 1 | grep "Product Name:" | sed 's/[^:]*:[ ]*//'`.chomp
            answer(oid)
            answer("string")
            answer(output)
        else
            answer("NONE")
        end
    else
        # oid is NONE or is not known
        answer("NONE")
    end
end

while true do

    command = gets.chomp

    case command

        when ''
            log("stopping rb_snmp_pass pass_persist script")
            exit(0)

        when 'PING'
            # yes, I am alive!
            answer("PONG")

        when 'get'
            # get command!
            oid = gets.chomp
            if is_fulloid_correct(oid)
                #answer(oid)
                get_oid_response(oid)
            else 
                answer("NONE")
            end
            
        when 'getnext'
            # getnext or walk command!
            oid = gets.chomp
            if is_oid_correct(oid)
                nextoid = get_next_oid(oid)
                get_oid_response(nextoid)
            else
                answer("NONE")
            end

        else
            log("Unknown command: #{command}")
            answer("")
    end

    sleep 0.0001 # avoid eating CPU due tty problems

end

## vim:ts=4:sw=4:expandtab:ai:nowrap:formatoptions=croqln:
