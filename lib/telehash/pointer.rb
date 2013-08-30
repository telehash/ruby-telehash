module Telehash
  class Pointer
    attr_reader :hashname, :ip, :port
    
    def self.parse see_line
      Pointer.new *see_line.split(",")
    end
    
    def initialize hashname, ip, port
      @hashname, @ip, @port = hashname, ip, port
    end
    
    def to_s
      "#{hashname},#{ip},#{port}"
    end
  end
end