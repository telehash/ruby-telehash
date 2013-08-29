require 'openssl'
require 'digest'
require 'base64'

module Telehash::Packet
  class Open
    attr_reader :switch, :peer, :family
    attr_reader :incoming
    attr_reader :line, :at, :ec
    attr_reader :instantiated_at
    attr :packet

    public
    def self.parse switch, packet, udpsocket_or_host, port = nil
      
      if packet.is_a? String
        packet = Telehash::RawPacket.parse packet
      end
      
      unless packet["type"].eql? "open"
        raise ArgumentError.new "Packet is not an open packet"
      end
      
      sender_ec_public_key_data = switch.decrypt Base64.decode64 packet["open"]
      ec = ec_point_from_data sender_ec_public_key_data

      iv = [packet["iv"]].pack("H*")
      inner_packet = decrypt_inner_packet ec, iv, packet.data
      
      unless inner_packet["to"].eql? switch.hashname
        raise ArgumentError.new "Packet was not meant for my hashname"
      end
      
      at = inner_packet["at"]
      unless at.is_a? Numeric
        raise ArgumentError.new '"at" value is not a numeric type'
      end
      
      sender_rsa_public_key_data = inner_packet.data
      sender_hashname = Digest::SHA2.hexdigest sender_rsa_public_key_data
      srsapk = OpenSSL::PKey::RSA.new sender_rsa_public_key_data

      unless srsapk.verify(OpenSSL::Digest::SHA256.new, Base64.decode64(packet["sig"]), packet.data)
        raise ArgumentError.new "Inner packet was not signed by the sender's RSA public key"
      end

      family = inner_packet["family"]
      incoming = true
      instantiated_at = Time.now
      at = Time.at at/1000.0 #milliseconds
      line = inner_packet["line"]
      if port
        peer = switch.peer srsapk, udpsocket_or_host, port
      else
        peeraddr = udpsocket_or_host.peeraddr false
        peer = switch.peer srsapk, peeraddr[2], peeraddr[1]
      end
      Open.new packet, switch, peer, family, incoming, line, at, ec, instantiated_at
    end
    
    def self.generate switch, seed, family = nil
      unless seed.public_key
        raise ArgumentError.new "Peer does not have a public key"
      end

      iv   = SecureRandom.random_bytes 16
      
      at       = Time.now
      incoming = false
      line     = SecureRandom.random_bytes 16
      ec       = generate_ec
      instantiated_at = at
      
      encrypted_public_ec = seed.encrypt_ec ec
    
      inner_packet = create_inner_packet switch, seed, line, at
      encrypted_inner_packet = encrypt_inner_packet ec, iv, inner_packet
      outer_sig = switch.sign encrypted_inner_packet

      outer_packet = Telehash::RawPacket.new({
        type: "open",
        open: Base64.encode64(encrypted_public_ec),
        iv: iv.unpack("H*")[0],
        sig: Base64.encode64(outer_sig)
      },
      encrypted_inner_packet)
      
      if family
        outer_packet.json["family"] = family.to_s
      end
      packet = outer_packet
      peer = switch.peer seed.public_key, seed.ip, seed.port
      Open.new packet, switch, peer, family, incoming, line, at, ec, instantiated_at
    end
    
    def to_s
      self.packet.to_s
    end
    
    protected
    def initialize packet, switch, peer, family, incoming, line, at, ec, instantiated_at
      @packet, @switch, @peer, @family, @incoming, @line, @at, @ec, @instantiated_at = 
        packet, switch, peer, family, incoming, line, at, ec, instantiated_at
    end
    
    def self.encrypt_inner_packet ec, iv, packet
      cipher = inner_packet_cipher ec, iv
      cipher.update(packet.to_s) + cipher.final
    end
    
    def self.ec_point_from_data sender_public_key_data
      bn = OpenSSL::BN.new(sender_public_key_data, 2)
      OpenSSL::PKey::EC::Point.new ec_group, bn
    end
    
    def self.decrypt_inner_packet ec, iv, data
      cipher = inner_packet_cipher ec, iv, false
      decrypted_data = cipher.update(data) + cipher.final
      Telehash::RawPacket.parse decrypted_data
    end
    
    def self.inner_packet_key ec
      if ec.is_a? OpenSSL::PKey::EC
        ec_bin = ec.public_key.to_bn.to_s(2)
      elsif ec.is_a? OpenSSL::PKey::EC::Point
        ec_bin = ec.to_bn.to_s(2)
      else
        ec_bin = ec.to_s
      end
      key    = Digest::SHA2.digest ec_bin
    end
    
    def self.inner_packet_cipher ec, iv, encrypt = true
      cipher = OpenSSL::Cipher.new "AES-256-CTR"
      if encrypt
        cipher.encrypt
      else
        cipher.decrypt
      end
      cipher.key = inner_packet_key ec
      cipher.iv  = iv
      cipher
    end
    
    def self.generate_ec 
      ec = OpenSSL::PKey::EC.new ec_group
      ec.generate_key
    end
    
    def self.ec_group
      group = OpenSSL::PKey::EC::Group.new "prime256v1"
      group.point_conversion_form = :uncompressed
      group
    end

    def self.create_inner_packet switch, peer, line, at = nil
      if !line
        line = SecureRandom.hex 16
      elsif line.length == 16
        line = line.unpack('H*')[0]
      end
      
      if !at
        at = Time.now
      end

      at = (at.to_f * 1000).floor
      
      Telehash::RawPacket.new({
        to: peer.hashname,
        line: line,
        at: at
      }, switch.public_key_der)
    end
  end
end
