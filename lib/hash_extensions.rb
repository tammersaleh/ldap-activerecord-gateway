class Hash
  def symbolize_keys
    inject({}) do |options, (key, value)|
      options[key.to_sym] = value
      options
    end
  end  
end
