require 'openssl'
require 'digest'

module Telehash::Packet
  class Open
    attr_reader :switch, :peer
    attr_reader :line, :at, :ec, :peer
    attr_reader :parsed_at
    attr :packet
    
    def initialize switch, packet, udpsocket
      if packet.is_a? String
        packet = Packet.parse packet
      end
      
      unless packet["type"].eql? "open"
        raise ArgumentError.new "Packet is not an open packet"
      end

      open = packet["open"]
      sender_ec_public_key_data = @key.private_decrypt(Base64.decode64(open), OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      
      @ec = ec_point_from_data sender_ec_public_key_data

      inner_packet = decrypt_inner_packet secpk, [packet["iv"]].pack("H*"), packet.data
      
      unless inner_packet["to"].eql? switch.hashname
        raise ArgumentError.new "Packet was not meant for my hashname"
      end
      
      at = inner_packet["at"]
      unless at.is_a? Numeric
        raise ArgumentError.new '"at" value is not a numeric type'
      end
      @at = Time.at at/1000.0
      @parsed_at = Time.now
      @line = inner_packet["line"]
      
      sender_rsa_public_key_data = inner_packet.data
      sender_hashname = Digest::SHA2.hexdigest sender_rsa_public_key_data
      srsapk = OpenSSL::PKey::RSA.new sender_rsa_public_key_data

      unless srsapk.verify(OpenSSL::Digest::SHA256.new, Base64.decode64(packet["sig"]), packet.data)
        raise ArgumentError.new "Inner packet was not signed by the sender's RSA public key"
      end


      @peer = switch.peer srsapk, ip, port
    end
  end
end