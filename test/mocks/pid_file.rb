class MockPidFile
  def pid; nil; end
  def remove; true; end
  def create; true; end
  def ensure_empty!(args = nil); true; end
end

