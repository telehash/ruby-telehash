require 'digest'
require 'openssl'

module Telehash::Core
  class Channel
    attr_reader :line, :id
       
    def initialize line, id = nil
      @line = line

      if id.nil?
        id = SecureRandom.hex 16
      end
      # in case we are being fed binary instead of hex, meh.
      if id.length == 16
        id = id.unpack("H*")[0]
      end
      @id = id
    end
    
    def peer
      line.peer
    end
  end
end