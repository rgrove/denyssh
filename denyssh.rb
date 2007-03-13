#!/usr/local/bin/ruby
#
# = DenySSH
#
# Monitors the system's auth log for failed SSH login attempts and adds
# attackers to a PF table, allowing you to define PF rules to either block the
# attacking hosts or redirect them to a honeypot for your amusement.
#
# Version::   1.0.0-beta
# Author::    Ryan Grove (mailto:ryan@wonko.com)
# Copyright:: Copyright (c) 2006 Ryan Grove
# License::   BSD-style (see below)
# Website::   http://wonko.com/software/denyssh
#
# === Dependencies
#
# * Ruby[http://ruby-lang.org/] 1.8.4
# * {Packet Filter}[http://openbsd.org/faq/pf/] (if you're running a recent
#   version of OpenBSD, FreeBSD, NetBSD, or DragonFlyBSD, you probably already
#   have PF installed)
#
# === License
#
# Copyright 2006 Ryan Grove. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#   1. Redistributions of source code must retain the above copyright notice,
#      this list of conditions and the following disclaimer.
#   2. Redistributions in binary form must reproduce the above copyright notice,
#      this list of conditions and the following disclaimer in the documentation
#      and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# ORIGINAL AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
# PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
# EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# :title: DenySSH
#

require 'fileutils'
require 'ipaddr'
require 'optparse'
require 'syslog'
require 'time'
require 'yaml'

PREFIX = '/usr/local'

################################################################################
# Class: IPAddr
###############

class IPAddr

  def <=>(other_addr)
    @addr <=> other_addr.to_i
  end

end # class IPAddr

################################################################################
# Class: Host
#############

module DenySSH

  # Represents a host that has connected (or attempted to connect) to the SSH
  # server.
  class Host

    attr_accessor :blocked_until
    attr_reader   :ip, :seen, :logins, :failures, :recent_failures

    def initialize(user, ip, successful)
      @ip              = ip
      @seen            = nil
      @logins          = 0
      @failures        = 0
      @recent_failures = 0
      @blocked_until   = nil

      update(user, successful)
    end

    def block
      if @blocked_until.nil?
        DenySSH.block(@ip)
        Syslog::log(Syslog::LOG_INFO, 'blocking %s', @ip)
      end

      @blocked_until = Time.now + (DenySSHConfig::BLOCK_MULTIPLIER *
        @recent_failures * 60)
    end

    def update(username, successful)
      @seen = Time.now

      if successful
        @logins += 1
        @recent_failures = 0
      else
        @failures += 1
        @recent_failures += 1

        # Root threshold.
        if @logins == 0 &&
            username == 'root' &&
            @recent_failures >= DenySSHConfig::DENY_THRESHOLD_ROOT

          self.block

        # Invalid threshold.
        elsif @logins == 0 &&
            @recent_failures >= DenySSHConfig::DENY_THRESHOLD_INVALID

          self.block

        # Valid threshold.
        elsif @recent_failures >= DenySSHConfig::DENY_THRESHOLD_VALID

          self.block

        end
      end
    end

  end # class Host

end

################################################################################
# Class: Tail
#############

module DenySSH

  # Provides <tt>tail -f</tt> functionality used to monitor a log file for
  # changes. Automatically reopens the file if it is truncated or deleted.
  class Tail

    attr_accessor :interval
    attr_reader   :filename, :last_change, :last_pos

    def initialize(filename, interval = 15, last_pos = 0)
      @filename    = filename
      @interval    = interval
      @last_pos    = last_pos
      @last_stat   = nil
    end

    # Begins tailing the file. When a new line appears, it's passed to the
    # block.
    def tail(&block) # :yields: line
      # Wait for the file to be created if it doesn't already exist.
      until File.exist?(@filename)
        sleep 30
      end

      # Make sure the file isn't a directory.
      if File.directory?(@filename)
        if Syslog::opened?
          Syslog::log(Syslog::LOG_ERR, 'error: %s is a directory', @filename)
          Syslog::log(Syslog::LOG_INFO, 'shutting down')
          Syslog::close
        end

        abort "** Error: #{@filename} is a directory"
      end

      # Begin watching the file.
      File.open(@filename) do |@file|
        begin
          @file.pos = @last_pos if @last_pos > 0
        rescue EOFError
          @file.rewind
        end

        loop do
          _restat

          changed = false

          while line = @file.gets
            changed = true
            yield line
          end

          @last_pos = @file.pos if changed
          @file.seek(0, File::SEEK_CUR)

          sleep @interval
        end
      end
    end

    private

    # Reopens the file. This is necessary if the file is deleted or truncated
    # while we're watching it.
    def _reopen
      @file.reopen(@filename)
      @last_pos = 0

      Syslog::log(Syslog::LOG_INFO, 'reopening %s', @filename)

    rescue Errno::ENOENT
    rescue Errno::ESTALE
      # File isn't there. Wait for it to reappear.
      sleep 15
      retry
    end

    # Performs various checks to determine whether we should reopen the file.
    def _restat
      stat = File.stat(@filename)

      if !@last_stat.nil?
        if stat.ino != @last_stat.ino || stat.dev != @last_stat.dev
          # File was replaced. Reopen it.
          @last_stat = nil
          _reopen
        elsif stat.size < @last_stat.size
          # File was truncated. Reopen it.
          @last_stat = nil
          _reopen
        end
      else
        @last_stat = stat
      end

    rescue Errno::ENOENT
    rescue Errno::ESTALE
      # File was deleted. Attempt to reopen it.
      _reopen
    end

  end # class Tail

end

################################################################################
# Module: DenySSHConfig
#######################

module DenySSHConfig

  @default = {
    :LOGFILE  => '/var/log/auth.log',
    :WORKDIR  => '/var/db/denyssh/hosts.yaml',
    :PFCTL    => '/sbin/pfctl',
    :PF_TABLE => 'denyssh',

    :DENY_THRESHOLD_VALID      => 10,
    :DENY_THRESHOLD_INVALID    => 5,
    :DENY_THRESHOLD_ROOT       => 3,

    :BLOCK_MULTIPLIER => 30,

    :PATTERNS_ACCEPT => [
      /sshd\[\d+\]: Accepted \S+ for (\S+) from ([\d\.]+)/,
    ],

    :PATTERNS_FAIL => [
      /sshd\[\d+\]: Illegal user (\S+) from ([\d\.]+)/,
      /sshd\[\d+\]: Failed \S+ for (?:invalid user\s+)?(\S+) from ([\d\.]+)/,
    ],
  }

  def self.const_missing(name)
    @default[name]
  end

  def self.load_config(config_file)
    unless File.exist?(config_file)
      abort "Config file not found: #{config_file}"
    end

    begin
      load config_file
    rescue Exception => e
      message = e.message.gsub("\n", '; ')

      if Syslog::opened?
        Syslog::log(Syslog::LOG_ERR, 'configuration error in %s: %s',
          config_file, message)
        Syslog::close
      end

      abort "Configuration error in #{config_file}: #{message}"
    end
  end

end # module DenySSHConfig

################################################################################
# Module: DenySSH
#################

module DenySSH
  APP_NAME    = 'DenySSH'
  APP_VERSION = '1.0.0-beta'

  @data    = Hash.new
  @threads = Hash.new

  # Adds the given IP address or array of IP addresses to the PF table.
  def self.block(addresses)
    if addresses.is_a? Array
      system("#{DenySSHConfig::PFCTL} -t \"#{DenySSHConfig::PF_TABLE}\" -T add #{addresses.join(' ')} > /dev/null 2>&1")
    else
      system("#{DenySSHConfig::PFCTL} -t \"#{DenySSHConfig::PF_TABLE}\" -T add #{addresses} > /dev/null 2>&1")
    end
  end

  # Clears all hosts from the PF table.
  def self.flush_table
    system("#{DenySSHConfig::PFCTL} -t \"#{DenySSHConfig::PF_TABLE}\" -T flush > /dev/null 2>&1")
  end

  # Loads host data from the host data file or initializes a new data hash if
  # the data file doesn't exist.
  def self.load_data
    if File.exist?(DenySSHConfig::HOSTDATA)
      @data = YAML.load_file(DenySSHConfig::HOSTDATA)
    else
      @data = {
        'lastpos' => 0,
        'hosts'   => Hash.new
      }
    end
  end

  # Monitors the auth log, taking action as new log entries are seen.
  def self.monitor
    # Unblock thread (unblocks hosts when their block times expire).
    @threads[:unblock] = Thread.new do
      loop do
        sleep 60

        now          = Time.now
        unblock_list = []

        @data['hosts'].each_value do |host|
          next if host.blocked_until.nil?

          if host.blocked_until <= now
            host.blocked_until = nil
            unblock_list << host.ip
          end
        end

        unblock(unblock_list) if unblock_list.length > 0
      end
    end

    # Data write thread.
    @threads[:data] = Thread.new do
      loop do
        sleep 120
        save_data
      end
    end

    # Maintenance thread.
    @threads[:maint] = Thread.new do
      loop do
        sleep 3600
        _clean_hosts
      end
    end

    Syslog::log(Syslog::LOG_INFO, "monitoring %s", DenySSHConfig::LOGFILE)

    # Monitor the log file for new entries.
    @tail = Tail.new(DenySSHConfig::LOGFILE, 15, @data['lastpos'])
    @tail.tail {|line| _analyze_entry(line) }
  end

  # Saves host data to the host data file.
  def self.save_data
    data_dir = File.dirname(DenySSHConfig::HOSTDATA)
    
    unless File.exists?(data_dir)
      FileUtils.mkdir_p(data_dir)
      File.chmod(0750, data_dir)
    end

    @data['lastpos'] = @tail.last_pos

    File.open(DenySSHConfig::HOSTDATA, 'w') do |file|
      YAML.dump(@data, file)
    end
    
    File.chmod(0640, DenySSHConfig::HOSTDATA)
    
  rescue Exception => e
    if Syslog::opened?
      Syslog::log(Syslog::LOG_ERR, 'error saving host data: %s', e)
    else
      STDERR.puts("Error saving host data: #{e}")
    end
  end

  # Opens a connection to syslog and loads the config file and host data file.
  def self.start(config_file)
    Syslog::open('denyssh', 0, Syslog::LOG_AUTH)

    for sig in [:SIGINT, :SIGQUIT, :SIGTERM]
      trap(sig) { stop }
    end

    DenySSHConfig::load_config(config_file)

    load_data
    flush_table
    update_table
  end

  def self.start_daemon(config_file)
    # Check the pid file to see if the app is already running.
    if File.file?('/var/run/denyssh.pid')
      STDERR.puts 'denyssh already running? (pid=' +
          File.read('/var/run/denyssh.pid', 20).strip + ')'
      abort
    end

    puts "Starting denyssh."

    # Fork off and die.
    fork do
      Process.setsid
      exit if fork

      # Write pid file.
      File.open('/var/run/denyssh.pid', 'w') {|file| file << Process.pid }

      # Release old working directory.
      Dir.chdir('/')

      # Reset umask.
      File.umask(0000)

      # Disconnect file descriptors.
      STDIN.reopen('/dev/null')
      STDOUT.reopen('/dev/null', 'a')
      STDERR.reopen(STDOUT)

      # Begin monitoring the auth log.
      start(config_file)
      monitor
    end
  end

  # Saves host data, closes the syslog connection, and exits the application.
  def self.stop
    save_data
    flush_table

    if Syslog::opened?
      Syslog::log(Syslog::LOG_INFO, 'shutting down')
      Syslog::close
    end

    exit
  end

  def self.stop_daemon
    unless File.file?('/var/run/denyssh.pid')
      STDERR.puts 'denyssh not running? (check /var/run/denyssh.pid).'
      abort
    end

    puts 'Stopping denyssh.'

    pid = File.read('/var/run/denyssh.pid', 20).strip
    FileUtils.rm('/var/run/denyssh.pid')
    pid && Process.kill('TERM', pid.to_i)
  end

  # Removes the given IP address or array of IP addresses from the PF table.
  def self.unblock(addresses)
    if addresses.is_a? Array
      system("#{DenySSHConfig::PFCTL} -t \"#{DenySSHConfig::PF_TABLE}\" -T delete #{addresses.join(' ')} > /dev/null 2>&1")
    else
      system("#{DenySSHConfig::PFCTL} -t \"#{DenySSHConfig::PF_TABLE}\" -T delete #{addresses} > /dev/null 2>&1")
    end
  end

  # Updates the PF table, blocking and unblocking hosts as necessary.
  def self.update_table
    now          = Time.now
    block_list   = []
    unblock_list = []

    @data['hosts'].each_value do |host|
      next if host.blocked_until.nil?

      if host.blocked_until > now
        block_list << host.ip
      elsif host.blocked_until <= now
        host.blocked_until = nil
        unblock_list << host.ip
      end
    end

    block(block_list) if block_list.length > 0
    unblock(unblock_list) if unblock_list.length > 0
  end

  private

  # Analyzes a log entry.
  def self._analyze_entry(line)
    DenySSHConfig::PATTERNS_ACCEPT.each do |pattern|
      next unless line =~ pattern

      if @data['hosts'].include?($2)
        @data['hosts'][$2].update($1, true)
      else
        @data['hosts'][$2] = Host.new($1, $2, true)
      end

      return
    end

    DenySSHConfig::PATTERNS_FAIL.each do |pattern|
      next unless line =~ pattern

      if @data['hosts'].include?($2)
        @data['hosts'][$2].update($1, false)
      else
        @data['hosts'][$2] = Host.new($1, $2, false)
      end

      return
    end
  end

  # Forgets hosts that aren't blocked and haven't been seen in over a month.
  def self._clean_hosts
    now = Time.now

    @data['hosts'].delete_if do |ip, host|
      host.blocked_until.nil? && now - host.seen >= 2678400
    end
  end

  ##############################################################################
  # Main
  ######

  if __FILE__ == $0
    options     = {
      'config_file' => ENV['DENYSSH_CONF'] || File.join(PREFIX,
          'etc/denyssh.conf'),
      'command' => :start,
      'mode'    => :monitor,
    }

    optparse = OptionParser.new do |optparse|
      optparse.summary_width  = 24
      optparse.summary_indent = '  '

      optparse.banner = 'Usage: denyssh [options]'

      optparse.separator ''
      optparse.separator 'Options:'

      optparse.on('-c', '--config [filename]',
          'Use the specified configuration file.') do |filename|
        options['config_file'] = filename
      end

      optparse.on('-d', '--daemon [command]', [:start, :stop, :restart],
          'Issue the specified command (start, stop, or restart)',
          'to the denyssh daemon.') do |command|
        options['mode']    = :daemon
        options['command'] = command
      end

      optparse.on_tail('-h', '--help',
          'Display usage information (this message).') do
        puts optparse
        exit
      end

      optparse.on_tail('-v', '--version',
          'Display version information.') do
        puts "#{APP_NAME} v#{APP_VERSION} <http://wonko.com/software/denyssh/>"
        puts 'Copyright (c) 2006 Ryan Grove <ryan@wonko.com>. All rights reserved.'
        puts
        puts "#{APP_NAME} comes with ABSOLUTELY NO WARRANTY."
        puts
        puts 'This program is open source software distributed under a BSD-style license. For'
        puts 'details, see the LICENSE file contained in the source distribution.'
        exit
      end
    end

    begin
      optparse.parse!(ARGV)
    rescue => e
      abort("Error: #{e}")
    end

    case options['mode']
      when :daemon
        case options['command']
          when :start
            start_daemon(File.expand_path(options['config_file']))

          when :stop
            stop_daemon

          when :restart
            stop_daemon
            start_daemon(File.expand_path(options['config_file']))

          else
            STDERR.puts 'Invalid command. Please specify start, stop, or ' +
              'restart.'
            abort
        end

      when :monitor
        # Begin monitoring the auth log.
        start(options['config_file'])
        monitor
    end
  end

end # module DenySSH
