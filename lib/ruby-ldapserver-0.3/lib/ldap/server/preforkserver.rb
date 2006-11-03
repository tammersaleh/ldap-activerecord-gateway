require 'prefork'	# <http://raa.ruby-lang.org/project/prefork/>
require 'socket'

module LDAP
class Server

  # Accept connections on a port, and for each one run the given block
  # in one of N pre-forked children. Returns a Thread object for the
  # listener.
  #
  # Options:
  #   :port=>port number [required]
  #   :bindaddr=>"IP address"
  #   :user=>"username"				- drop privileges after bind
  #   :group=>"groupname"			- ditto
  #   :logger=>object				- implements << method
  #   :listen=>number				- listen queue depth
  #   :nodelay=>true				- set TCP_NODELAY option
  #   :min_servers=>N				- prefork parameters
  #   :max_servers=>N
  #   :max_requests_per_child=>N
  #   :max_idle=>N				- seconds

  def self.preforkserver(opt, &blk)
    logger = opt[:logger] || $stderr
    server = PreFork.new(opt[:bindaddr] || "0.0.0.0", opt[:port])

    # Drop privileges if requested
    if opt[:group] or opt[:user]
      require 'etc'
      gid = Etc.getgrnam(opt[:group]).gid if opt[:group]
      uid = Etc.getpwnam(opt[:user]).uid if opt[:user]
      File.chown(uid, gid, server.instance_eval {@lockf})
      Process.gid = Process.egid = gid if gid
      Process.uid = Process.euid = uid if uid
    end

    # Typically the O/S will buffer response data for 100ms before sending.
    # If the response is sent as a single write() then there's no need for it.
    if opt[:nodelay]
      begin
        server.sock.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      rescue Exception
      end
    end
    # set queue size for incoming connections (default is 5)
    server.sock.listen(opt[:listen]) if opt[:listen]

    # Set prefork server parameters
    server.min_servers = opt[:min_servers] if opt[:min_servers]
    server.max_servers = opt[:max_servers] if opt[:max_servers]
    server.max_request_per_child = opt[:max_request_per_child] if opt[:max_request_per_child]
    server.max_idle = opt[:max_idle] if opt[:max_idle]

    Thread.new do
      server.start do |s|
        begin
          s.instance_eval(&blk)
        rescue Interrupt
          # This exception can be raised to shut the server down
          server.stop
        rescue Exception => e
          logger << "[#{s.peeraddr[3]}]: #{e}: #{e.backtrace[0]}\n"
        ensure
          s.close
        end
      end
    end
  end

end # class Server
end # module LDAP

if __FILE__ == $0
  # simple test
  puts "Running a test POP3 server on port 1110"
  t = LDAP::Server.preforkserver(:port=>1110) do
    print "+OK I am a fake POP3 server (pid #{$$})\r\n"
    while line = gets
      case line
      when /^quit/i
        break
      when /^crash/i
        raise Errno::EPERM, "dammit!"
      else
        print "-ERR I don't understand #{line}"
      end
    end
    print "+OK bye\r\n"
  end
  #sleep 10; t.raise Interrupt	# uncomment to run for fixed time period
  t.join
end
