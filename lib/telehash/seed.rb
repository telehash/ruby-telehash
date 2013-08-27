require 'openssl'
require 'json'
require 'ipaddr'

module Telehash
  class Seed
    attr_accessor :ip, :port, :public_key 
    attr_reader :hashname
    
    def initialize (json_or_options)
      if json_or_options.is_a? String
        json_or_options = JSON.parse json_or_options
      end
      if !json_or_options.is_a?(Hash)
        raise ArgumentError.new "input must be a string or hash"
      end
      @ip = IPAddr.new(json_or_options[:ip] || json_or_options["ip"])
      @port = (json_or_options[:port] || json_or_options["port"]).to_i
      @public_key = OpenSSL::PKey::RSA.new (json_or_options[:pubkey] || json_or_options["pubkey"])
      @hashname = (json_or_options[:hashname] || json_or_options["hashname"]).dup.freeze
      computed_hash = Digest::SHA2.hexdigest @public_key.to_der
      if @hashname
        unless @hashname.eql? computed_hash
          raise ArgumentError.new "specified hashname does not match hash of key"
        end
      else
        @hashname = computed_hash.freeze
      end
    end
    
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
    
    def encrypt_ec ec
      if ec.group.point_conversion_form != :uncompressed
        raise ArgumentException.new "Compressed Elliptic Curves not supported"
      end
      if ec.is_a? OpenSSL::PKey::EC
        point = ec.public_key
      else
        point = ec
      end
      
      bin = point.to_bn.to_s(2)
      public_key.public_encrypt(bin, 
        OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
    end
  end
end
