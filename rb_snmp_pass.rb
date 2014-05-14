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
#   1             2                3                 4                5             6               7              8          9            10
# index |      statName     | statInstance | statInstancesGroup | statState | statTimestamp | statTimesticks | statString | statValue | statUnit
# ------+-------------------+--------------+--------------------+-----------+---------------+----------------+------------+-----------+---------
#   1   | pkt_drop_percent  |      0       |         0          |     1     |   1396511411  |      300       |   "0.02"   |     20    |    4
# ------+-------------------+--------------+--------------------+-----------+---------------+----------------+------------+-----------+---------
#   2   | alerts_per_second |      0       |         0          |     1     |   1396511411  |      300       |   "6.00"   |     6000  |    5
# ------+-------------------+--------------+--------------------+-----------+---------------+----------------+------------+-----------+---------
#  ...  |        ...        |     ...      |        ...         |    ...    |      ...      |      ...       |     ...    |     ...   |   ...

# params: time, wire_mbits_per_sec.realtime, pkt_drop_percent, kpackets_wire_per_sec.realtime, total_sessions, idle[x], alerts_per_minute

require 'syslog'

BASEOID = ".1.3.6.1.4.1.39483"
NUMSEQUENCE = 10
NUMCPUS = 1 # this value is for global community. In redBorder v2, NUMCPUS=8 and snort.stats is under others directories.
STATUNIT = { :none => 0,
             :avg => 1,
             :mbps => 2,
             :kpps => 3,
             :percent => 4,
             :aps => 5
           }
PARAMS = [  { :statName => "pkt_drop_percent", :statUnit => STATUNIT[:percent] },
            { :statName => "alerts_per_second", :statUnit => STATUNIT[:aps] },
            { :statName => "kpackets_wire_per_sec.realtime", :statUnit => STATUNIT[:kpps] },
            { :statName => "wire_mbits_per_sec.realtime", :statUnit => STATUNIT[:mbps] },
            { :statName => "total_sessions", :statUnit => STATUNIT[:none] },
            { :statName => "cpu_usage", :statUnit => STATUNIT[:percent] }
         ]
NUMSTATS = PARAMS.count * NUMCPUS

def log(message)
    Syslog.open("rb_snmp_pass", Syslog::LOG_PID | Syslog::LOG_CONS) { |s| s.warning message }
end

def answer(message)
    puts "#{message}"
    $stdout.flush
end

def is_oid_correct(oid)
    m = /^#{BASEOID}(\.10(\.1(\.3(\.1(\.((?<sequence>\d+)(\.(?<index>\d+))?)?)?)?)?)?)?$/.match(oid)
    if m 
        if m[:sequence].nil?
            true
        else
            if (2..NUMSEQUENCE).include? m[:sequence].to_i
                if m[:index].nil?
                    true
                else
                    if (1..NUMSTATS).include? m[:index].to_i
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

def is_fulloid_correct(oid)
    m = /^#{BASEOID}\.10\.1\.3\.1\.(?<sequence>\d+)\.(?<index>\d+)$/.match(oid)
    if m and ((2..NUMSEQUENCE).include? m[:sequence].to_i) and ((1..NUMSTATS).include? m[:index].to_i)
        true
    else
        false
    end
end

def read_stats_from_file(h)
    # calculate stats values for a group and instance
    if File.file?("/var/log/snort/stats/snort.stats")
        statHash = Hash.new
        statFile = IO.readlines("/var/log/snort/stats/snort.stats")
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
    instance = 0
    output = ""
    m = /^#{BASEOID}\.10\.1\.3\.1\.(?<sequence>\d+)\.(?<index>\d+)$/.match(oid)
    if m and ((m[:sequence].to_i == 2) and ((1..NUMSTATS).include? m[:index].to_i))
        # send stat name
        answer(oid)
        answer("string")
        answer(PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName])
    elsif m and ((m[:sequence].to_i == 3) and ((1..NUMSTATS).include? m[:index].to_i))
        # send instance number
        answer(oid)
        answer("integer")
        answer("#{(m[:index].to_i-1)%NUMCPUS}")
    elsif m and ((m[:sequence].to_i == 4) and ((1..NUMSTATS).include? m[:index].to_i))
        # send instances group number (always 0 in version 2.2.28)
        answer(oid)
        answer("integer")
        answer("0")
    elsif m and ((m[:sequence].to_i == 5) and ((1..NUMSTATS).include? m[:index].to_i))
        # send stat state
        instance = (m[:index].to_i-1)%NUMCPUS
        output = read_stats_from_file({:instance => instance, :statname => "time"})
        if /^([\d\.]*)+$/.match(output)
            answer(oid)
            answer("integer")
            answer("1")
        else
            answer(oid)
            answer("integer")
            answer("0")
        end
    elsif m and ((m[:sequence].to_i == 6) and ((1..NUMSTATS).include? m[:index].to_i))
        # send timestamp
        instance = (m[:index].to_i-1)%NUMCPUS
        output = read_stats_from_file({:instance => instance, :statname => "time"})
        if /^([\d\.]*)+$/.match(output)
            answer(oid)
            answer("integer")
            answer("#{output}")
        else
            # error reading time from stats?
            answer(oid)
            answer("integer")
            answer("0")
        end
    elsif m and ((m[:sequence].to_i == 7) and ((1..NUMSTATS).include? m[:index].to_i))
        # send timestamp
        instance = (m[:index].to_i-1)%NUMCPUS
        output = read_stats_from_file({:instance => instance, :statname => "time"})
        if /^([\d\.]*)+$/.match(output)
            answer(oid)
            answer("timeticks")
            answer("#{(Time.now.to_i - output.to_i) * 100}")
        else
            # error reading time from stats?
            answer(oid)
            answer("timeticks")
            answer("0")
        end
    elsif m and ((m[:sequence].to_i == 8) and ((1..NUMSTATS).include? m[:index].to_i))
        # send stat value in string
        instance = (m[:index].to_i-1)%NUMCPUS
        if PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName] == "cpu_usage"
            # in 2.2.28, instance = #cpu !!! ... in horama (3.x) #cpu need to get from instance environment
            idlename = "idle[#{instance}]"
            output = read_stats_from_file({:instance => instance, :statname => idlename})
        else
            output = read_stats_from_file({:instance => instance, :statname => PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName]})
        end
        if /^([\d\.]*)+$/.match(output)
            if PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName] == "cpu_usage"
                output = (100 - output.to_f).round(3)
            end
            answer(oid)
            answer("string")
            answer("#{output}")
        else
            # error reading from stats?
            answer(oid)
            answer("string")
            answer("undef")
        end
    elsif m and ((m[:sequence].to_i == 9) and ((1..NUMSTATS).include? m[:index].to_i))
        # send stat value in integer
        instance = (m[:index].to_i-1)%NUMCPUS
        if PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName] == "cpu_usage"
            # in 2.2.28, instance = #cpu !!! ... in horama (3.x) #cpu need to get from instance environment
            idlename = "idle[#{instance}]"
            output = read_stats_from_file({:instance => instance, :statname => idlename})
        else
            output = read_stats_from_file({:instance => instance, :statname => PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName]})
        end
        #output = read_stats_from_file({:instance => instance, :statname => PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName]})
        if /^([\d\.]*)+$/.match(output)
            if PARAMS[(m[:index].to_i-1)/NUMCPUS][:statName] == "cpu_usage"
                output = (100 - output.to_f).round(3)
            end
            answer(oid)
            answer("integer")
            outputnum = output.to_f * 1000
            answer("#{outputnum.to_i}")
        else
            # error reading from stats?
            answer(oid)
            answer("integer")
            answer("0")
        end
    elsif m and ((m[:sequence].to_i == 10) and ((1..NUMSTATS).include? m[:index].to_i))
        # send stat value
        answer(oid)
        answer("integer")
        answer(PARAMS[(m[:index].to_i-1)/NUMCPUS][:statUnit])
    else
        # oid is NONE or is not known
        answer("NONE")
    end
end

def get_next_oid(oid)
    ymax = NUMSTATS
    xmax = NUMSEQUENCE
    if /^#{BASEOID}(\.10(\.1(\.3(\.1(\.2)?)?)?)?)?$/.match(oid) 
        return "#{BASEOID}.10.1.3.1.2.1"
    else
        for x in (2..xmax) do
            if  /^#{BASEOID}\.10\.1\.3\.1\.#{x}$/.match(oid)
                return "#{BASEOID}.10.1.3.1.#{x}.1"
            else
                for y in (1..ymax) do
                    if x == xmax && y == ymax
                        return "NONE"
                    elsif /^#{BASEOID}\.10\.1\.3\.1\.#{x}\.#{y}$/.match(oid)
                        if y == ymax
                            return "#{BASEOID}.10.1.3.1.#{x+1}.1"
                        else
                            return "#{BASEOID}.10.1.3.1.#{x}.#{y+1}"
                        end
                    else
                        # continue next loop
                    end
                end
            end
        end
    end

    return "NONE"

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
