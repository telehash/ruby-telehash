require 'base64'
require 'openssl'
require 'securerandom'
require 'telehash/core/peer'

module Telehash::Core
  class Switch
    attr_reader :public_key, :hashvalue
    attr        :key
    attr        :public_key_der
    attr        :pending_lines, :peers
    
    def initialize(rsa_pkey)
      @key            = rsa_pkey
      @public_key     = rsa_pkey.public_key
      @public_key_der = rsa_pkey.public_key.to_der.freeze
      
      @pending_lines  = {} #hashname to EC key
      @peers          = {} #hashname to Peer or Seed

      @hashvalue      = OpenSSL::Digest::SHA256.digest @public_key_der
    end
    
    def peer_from_hashname hashname
      @peers[hashname]
    end
    
    def peer_from_addrinfo addrinfo
      @peers.each_value.find do |peer|
        addrinfo[1].eql?(peer.port) and addrinfo[2].eql?(peer.ip)
      end
    end

    def hashvalue
      @hashvalue ||= OpenSSL::Digest::SHA256.digest @public_key_der
    end
    
    def hashname
      self.hashvalue.unpack("H*").first
    end

    def decrypt data, padding = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      @key.private_decrypt data, padding
    end

    def decrypt64 data, padding = OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING
      @key.private_decrypt Base64.decode64(data), padding
    end
       
    def sign data, digest = OpenSSL::Digest::SHA256.new
      @key.sign digest, data
    end
    
    def to_s
      "Switch: hashname=#{self.hashname[0..7]}..."
    end
    
    def peer public_key, ip, port
      if public_key.is_a? String
        public_key = OpenSSL::PKey::RSA.new public_key
      end
      
      hashname = OpenSSL::Digest::SHA256.digest public_key.to_der
      
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
