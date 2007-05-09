class Person
  def self.count; 
    10
  end
  
  def self.search(*args)
    (1..10).map { |i| self.new(i) }
  end
  
  def initialize(i)
    @i = i
  end
  
  def to_ldap_entry
		entry = {
			"objectclass"     => ["top", "person", "organizationalPerson", "inetOrgPerson", "mozillaOrgPerson"],
			"uid"             => [@i.to_s],
 			"sn"              => ["LastName#{@i}"],
			"cn"              => ["FirstName#{@i}"],
			"givenName"       => ["LastName#{@i}"],
  		"telephonenumber" => ["555-121#{@i}"],
  		"homephone"       => ["555-122#{@i}"],
  		"fax"             => ["555-123#{@i}"],
  		"mobile"          => ["555-124#{@i}"],
  		"postofficebox"   => ["213 Lane St."],
  		"l"               => ["Chicago"],
  		"st"              => ["IL"],
  		"postalcode"      => ["02143"],
  		"title"           => ["Mr"],
  		"o"               => ["Some Company"],
  		"mail"            => ["user#{@i}@somecompany.com"],
		}

		return entry
  end
end
