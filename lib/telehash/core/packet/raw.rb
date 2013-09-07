require 'openssl'
require 'json'

module Telehash::Core::Packet
  # Represents a raw packet over the wire. Typically used to implement other
  # classes which understand the actual data.
  #
  # See https://github.com/telehash/telehash.org/blob/master/protocol.md#packets
  # for format
  class Raw
    # Accessors for the JSON and BODY portions of a message explicitly.
    attr_accessor :json, :body
    
    def self.parse raw_packet
      return raw_packet if raw_packet.is_a? RawPacket

      json_length, rest = raw_packet.to_s.unpack "nA*"
      json_string, body = rest.unpack "A#{json_length}A*"
      if (body && body.empty?)
        body = nil
      end
      Raw.new JSON.parse(json_string, symbolize_names: true), body
    end
    
    def initialize json, body = nil
      @json = json
      @body = body || json[:BODY]
    end
    
    def to_s
      json_text = @json.to_json
      [json_text.length, json_text, @body].pack "nA*A*"
    end
    
    def [] index
      if index.eql? :BODY
        @body
      else
        @json[index.to_sym]
      end
    end
    
    def []= index, value
      if index.eql? :BODY
        @body = value
      else
        @json[index.to_sym] = value
      end
    end
  end
end
