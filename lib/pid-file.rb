class Pidfile
  attr_reader :file
  def initialize(file)
    @file = file 
  end
  
  def pid
    File.file?(@file) and IO.read(@file) 
  rescue 
    puts "ERROR: attempt to read contents of #{@file} failed."
  end
  
  def remove
    if self.pid
      FileUtils.rm @file 
    end
  rescue 
    puts "ERROR: remove #{@file} failed."
  end
  
  def create
    File.open(@file, "w") { |f| f.write($$) }
  rescue 
    puts "ERROR: attempt to write #{file} failed."
    exit 2
  end
end
