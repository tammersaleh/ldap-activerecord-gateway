require 'fileutils'
class PidFile
  attr_reader :file
  def initialize(file)
    @file = file 
  end
  
  def pid
    File.file?(@file) and IO.read(@file) 
  end
  
  def remove
    if self.pid
      FileUtils.rm @file 
    end
  end
  
  def create
    File.open(@file, "w") { |f| f.write($$) }
  end
  
  def ensure_empty!(msg = nil)
    if self.pid
      puts msg if msg
      exit 1
    end
  end
end
