require 'digest'
require 'openssl'

module Telehash::Core
  class Line
    attr_reader :peer                            # for my RSA public key, hashname
    attr_reader :incoming_line, :outgoing_line   # incoming and outgoing line id's
    attr_reader :ip, :port                       # peer's IP and port
    attr_reader :outgoing_encrypt_cipher         # ciphers based on ECDHE key neg - NOT roundtrip!
    attr_reader :incoming_decrypt_cipher         # ciphers need to be reset, and get a new IV each time
       
    def initialize inbound_open, outbound_open
      @peer = inbound_open.peer
      
      unless outbound_open.switch.eql? inbound_open.switch
        raise ArgumentError.new "both packets must be from same switch"
      end
      
      unless outbound_open.peer.eql? @peer
        raise ArgumentError.new "both packets must be for the same peer"
      end
      
      @incoming_line = outbound_open.line
      @outgoing_line = inbound_open.line
      @ip   = @peer.ip
      @port = @peer.port
      
      ecdhe_secret = outbound_open.ec.dh_compute_key inbound_open.ec
      @outgoing_encrypt_cipher = form_cipher ecdhe_secret, true
      @incoming_encrypt_cipher = form_cipher ecdhe_secret, false
    end
    
    def form_cipher ecdhe_secret, encrypt = true
      cipher = OpenSSL::Cipher.new "AES-256-CTR"

      if encrypt
        key = Digest::SHA2.digest(ecdhe_secret + [@incoming_line].pack("H*") + [@outgoing_line].pack("H*"))
        cipher.encrypt
      else
        key = Digest::SHA2.digest(ecdhe_secret + [@outgoing_line].pack("H*") + [@incoming_line].pack("H*"))
        @incoming_decrypt_cipher.decrypt
      end
      cipher.key = key
      cipher
    end
    
    def pack_iv iv
      if (iv.length == 32)
        iv = [iv].pack("H*")
      end
      iv
    end
    
    def encrypt_outgoing data, iv
      iv = pack_iv iv
      begin
        @outgoing_encrypt_cipher.iv = iv
        @outgoing_encrypt_cipher.update(data.to_s) + @outgoing_encrypt_cipher.final
      ensure
        @outgoing_encrypt_cipher.reset
      end
    end
    
    def decrypt_incoming data, iv
      iv = pack_iv iv
      begin
        @incoming_decrypt_cipher.iv = iv
        @incoming_decrypt_cipher.update(data) + @incoming_decrypt_cipher.final
      ensure
        @incoming_decrypt_cipher.reset
      end
    end
  end
end
