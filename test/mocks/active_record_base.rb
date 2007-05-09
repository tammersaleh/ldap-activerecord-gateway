class ActiveRecord
  class Base
    class << self
      attr_accessor :allow_concurrency
    end
  end
end
