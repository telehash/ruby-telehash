require 'digest'
require 'openssl'

module Telehash
  class Line
    attr_reader :switch, :peer                   # for my RSA public key, hashname
    attr_reader :incoming_line, :outgoing_line   # incoming and outgoing line id's
    attr_reader :ip, :port                       # peer's IP and port
    attr_reader :outgoing_encrypt_cipher         # ciphers based on ECDHE key neg - NOT roundtrip!
    attr_reader :incoming_decrypt_cipher         # ciphers need to be reset, and get a new IV each time
       
    def initialize inbound_open, outbound_open
      @switch = inbound_open.switch
      @peer = inbound_open.peer
      unless outbound_open.switch.eql? switch
        raise ArgumentError.new "both packets must be from same switch"
      end
      unless outbound_open.peer.eql? peer
        raise ArgumentError.new "both packets must be for the same peer"
      end
      
      @incoming_line = inbound_open.line
      @outgoing_line = outbound_open.line
      @ip = @peer.ip
      @port = @peer.port
      
      ecdhe_secret = outbound_open.ec.dh_compute_key inbound_open.ec
      encrypt_cipher_key = Digest::SHA2.digest(ecdhe_secret + @outgoing_line + @incoming_line)
      @outgoing_encrypt_cipher = OpenSSL::Cipher.new "AES-256-CTR"
      @outgoing_encrypt_cipher.encrypt
      @outgoing_encrypt_cipher.key = encrypt_cipher_key
      
      decrypt_cipher_key = Digest::SHA2.digest(ecdhe_secret + @incoming_line + @outgoing_line)
      @incoming_decrypt_cipher = OpenSSL::Cipher.new "AES-256-CTR"
      @incoming_decrypt_cipher.decrypt
      @incoming_decrypt_cipher.key = decrypt_cipher_key
    end
  end
end
