require 'digest'
require 'base64'
require 'openssl'
require 'securerandom'
require 'telehash/peer'
require 'telehash/raw_packet'

module Telehash
  class Switch
    attr_reader :public_key
    attr        :hashname, :key, :public_key_der
    attr        :pending_lines, :peers
    
    def initialize(rsa_pkey)
      @key            = rsa_pkey
      @public_key     = rsa_pkey.public_key
      @public_key_der = rsa_pkey.public_key.to_der.freeze
      
      @pending_lines  = {} #hashname to EC key
      @peers          = {} #hashname to Peer or Seed
    end
    
    def hashname
      @hashname ||= Digest::SHA2.hexdigest @public_key_der
    end

    def decrypt data, padding = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      @key.private_decrypt data, padding
    end
       
    def sign data, digest = OpenSSL::Digest::SHA256.new
      @key.sign digest, data
    end 
    def to_s
      "Switch: hashname: #{self.hashname}"
    end
    
    def generate_open peer, family = nil
      Telehash::Packet::Open.generate self, peer, family
    end
    
    def peer public_key, ip, port
      if public_key.is_a? String
        public_key = OpenSSL::PKey::RSA.new public_key
      end
      
      hashname = Digest::SHA2.hexdigest public_key.to_der
      
      peer = @peers[hashname]
      if peer && peer.ip.eql?(ip) && peer.port.eql?(port)
        peer
      else
        peer = Peer.new ip: ip, port: port, pubkey: public_key
        peers[hashname] = peer
        peer
      end
    end
  end
end
