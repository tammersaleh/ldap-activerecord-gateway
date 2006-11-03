require 'socket'

module LDAP
class Server

  # Accept connections on a port, and for each one start a new thread
  # and run the given block. Returns the Thread object for the listener.
  #
  # FIXME:
  # - have a limit on total number of concurrent connects
  # - have a limit on connections from a single IP, or from a /24
  #   (to avoid the trivial DoS that the first limit creates)
  # - ACL using source IP address (or perhaps that belongs in application)
  #
  # Options:
  #   :port=>port number [required]
  #   :bindaddr=>"IP address"
  #   :user=>"username"				- drop privileges after bind
  #   :group=>"groupname"			- ditto
  #   :logger=>object				- implements << method
  #   :listen=>number				- listen queue depth
  #   :nodelay=>true				- set TCP_NODELAY option

  def self.tcpserver(opt, &blk)
    logger = opt[:logger] || $stderr
    server = TCPServer.new(opt[:bindaddr] || "0.0.0.0", opt[:port])

    # Drop privileges if requested
    require 'etc' if opt[:group] or opt[:user]
    Process.gid = Process.egid = Etc.getgrnam(opt[:group]).gid if opt[:group]
    Process.uid = Process.euid = Etc.getpwnam(opt[:user]).uid if opt[:user]
   
    # Typically the O/S will buffer response data for 100ms before sending.
    # If the response is sent as a single write() then there's no need for it.
    if opt[:nodelay]
      begin
        server.setsockopt(Socket::IPPROTO_TCP, Socket::TCP_NODELAY, 1)
      rescue Exception
      end
    end
    # set queue size for incoming connections (default is 5)
    server.listen(opt[:listen]) if opt[:listen]

    Thread.new do
      while true
        begin
          session = server.accept
          # subtlety: copy 'session' into a block-local variable because
          # it will change when the next session is accepted
          Thread.new(session) do |s|
            begin
              s.instance_eval(&blk)
            rescue Exception => e
              logger << "[#{s.peeraddr[3]}]: #{e}: #{e.backtrace[0]}\n"
              #logger << "[#{s.peeraddr[3]}]: #{e}: #{e.backtrace.join("\n\tfrom ")}\n"
            ensure
              s.close
            end
          end
        rescue Interrupt
          # This exception can be raised to shut the server down
          server.close if server and not server.closed?
          break
        end
      end
    end
  end

end # class Server
end # module LDAP

if __FILE__ == $0
  # simple test
  puts "Running a test POP3 server on port 1110"
  t = LDAP::Server.tcpserver(:port=>1110) do
    print "+OK I am a fake POP3 server\r\n"
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
