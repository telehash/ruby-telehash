require 'openssl'
require 'json'

module Telehash
  class Packet
    attr_accessor :json, :data
    
    def self.parse raw_packet
      json_length, rest = raw_packet.unpack "nA*"
      json_string, data = rest.unpack "A#{json_length}A*"
      if (data && data.empty?)
        data = nil
      end
      Packet.new JSON.parse(json_string), data
    end
    
    def initialize json, data = nil
      @json = json
      @data = data
    end
    
    def to_s
      json_text = @json.to_json
      [json_text.length, json_text, @data].pack "nA*A*"
    end
    
    def [] index
      if index.eql? "BODY"
        body
      else
        json[index]
      end
    end
    
    def []= index, value
      if index.eql? "BODY"
        body = value
      else
        json[index] = value
      end
    end
  end
end
