#!/usr/local/bin/ruby

require 'ldap'

CHILDREN = 10
CONNECTS = 1	# per child
SEARCHES = 100	# per connection

pids = []
CHILDREN.times do
  pids << fork do
    CONNECTS.times do
      conn = LDAP::Conn.new("localhost",1389)
      conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
      conn.bind
      SEARCHES.times do
        res = conn.search("cn=Fred Flintstone,dc=example,dc=com", LDAP::LDAP_SCOPE_BASE,
                          "(objectclass=*)") do |e|
          #puts "#{$$} #{e.dn.inspect}"
        end
      end
      conn.unbind
    end
  end
end
okcount = 0
badcount = 0
pids.each do |p|
  Process.wait(p)
  if $?.exitstatus == 0
    okcount += 1
  else
    badcount += 1
  end
end
puts "Children finished: #{okcount} ok, #{badcount} failed"
exit badcount > 0 ? 1 : 0
