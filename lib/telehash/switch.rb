require 'digest'
require 'base64'
require 'openssl'
require 'securerandom'
require 'telehash/seed'
require 'telehash/packet'

module Telehash
  class Switch
    attr_reader :public_key
    attr        :hashname
    
    def initialize(rsa_pkey)
      @key            = rsa_pkey.dup
      @public_key     = rsa_pkey.public_key
      @public_key_der = rsa_pkey.public_key.to_der.freeze
    end
    
    def hashname
      @hashname ||= Digest::SHA2.hexdigest @public_key_der
    end

    def generate_ec 
      ec_group = OpenSSL::PKey::EC::Group.new "prime256v1"
      ec_group.point_conversion_form = :uncompressed
      ec = OpenSSL::PKey::EC.new ec_group
      ec.generate_key
    end
    
    def generate_open seed
      ec = generate_ec
      iv = SecureRandom.random_bytes 16
      line = SecureRandom.random_bytes 16
      
      inner_packet = Packet.new({
        to:   seed.hashname,
        line: line.unpack("H*"),
        at:   (Time.now.to_f * 1000).floor
        }, @public_key_der)

      ec_public_bin = ec.public_key.to_bn.to_s(2)
      encrypted = seed.public_key.public_encrypt(ec_public_bin, OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      
      outer_packet = Packet.new({
        type: "open",
        open: ec.to_der.unpack("H*"),
        iv: iv.unpack("H*")
      })
    end      
  end
end
