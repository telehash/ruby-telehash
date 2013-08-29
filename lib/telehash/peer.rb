require 'json'
require 'digest'
require 'openssl'

module Telehash
  class Peer
    attr_reader :ip, :port, :public_key, :hashname
    # attr_accessible :open_at, :line

    def initialize (json_or_options)
      if json_or_options.is_a? String
        json_or_options = JSON.parse json_or_options
      end
      if !json_or_options.is_a?(Hash)
        raise ArgumentError.new "input must be a string or hash"
      end
      @ip = json_or_options[:ip] || json_or_options["ip"]
      @port = (json_or_options[:port] || json_or_options["port"]).to_i
      @public_key = OpenSSL::PKey::RSA.new (json_or_options[:pubkey] || json_or_options["pubkey"])
      @hashname = (json_or_options[:hashname] || json_or_options["hashname"])
      computed_hash = Digest::SHA2.hexdigest @public_key.to_der
      if @hashname
        @hashname = @hashname.dup.freeze
        if @hashname
          unless @hashname.eql? computed_hash
            raise ArgumentError.new "specified hashname does not match hash of key"
          end
        end
      else
        @hashname = computed_hash.freeze
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
    
    def to_s
      "Peer: { hashname:#{self.hashname} at #{self.ip}:#{self.port} }" 
    end
  end
end