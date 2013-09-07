require 'telehash/core/peer'
require 'openssl'
require 'json'
require 'ipaddr'

module Telehash::Core
  class Seed < Peer  
    def self.parse_all json
      if json.is_a? String
        json = JSON.parse json
      elsif json.is_a? File
        json = JSON.parse json.read
      elsif json.is_a? Array
        json = json.dup
      else
        raise ArgumentError.new "json must be a string, file, or array"
      end
      
      json.map do |seed| 
        Seed.new seed
      end
    end
  end
end
