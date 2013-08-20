require 'openssl'
require 'json'

module Telehash
  class Packet
    attr_accessor :json, :data
    
    def initialize json, data = nil
      @json = json
      @data = data
    end
    
    def to_s
      json_text = @json.to_json
      [json_text.length, json_text, @data].pack "nA*A*"
    end
  end
end
