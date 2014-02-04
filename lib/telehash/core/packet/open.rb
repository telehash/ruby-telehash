require 'openssl'
require 'digest'
require 'base64'

module Telehash::Core::Packet
  class Open
    attr :packet
    attr_reader :switch, :peer
    attr_reader :incoming
    attr_reader :line, :at, :ec
    attr_reader :instantiated_at

    def self.parse switch, packet, udpsocket_or_host, port = nil
      packet       = form_packet packet
      incoming_ec  = ec_point_from_data switch.decrypt64 packet[:open]
      iv           = from_hex packet[:iv]
      inner_packet = decrypt_inner_packet incoming_ec, iv, packet.body
      
      unless inner_packet[:to].eql? switch.hashname
        raise ArgumentError.new "Packet was not meant for my hashname"
      end
      
      line = inner_packet[:line]
      decrypted_signature = decrypt_signature packet[:sig], incoming_ec, line, iv

      srsapk = OpenSSL::PKey::RSA.new inner_packet.body
      unless srsapk.verify(OpenSSL::Digest::SHA256.new, decrypted_signature, packet.body)
        raise ArgumentError.new "Inner packet was not signed by the sender's RSA public key"
      end

      at   = parse_at inner_packet
      peer = form_peer switch, srsapk, udpsocket_or_host, port

      Open.new packet, switch, peer, true, line, at, incoming_ec
    end

    def self.generate switch, seed
      unless seed.public_key
        raise ArgumentError.new "Peer does not have a public key"
      end

      iv   = SecureRandom.random_bytes 16
      
      at       = Time.now
      incoming = false
      line     = SecureRandom.hex 16
      ec       = generate_ec
      instantiated_at = at
      
      encrypted_public_ec = seed.encrypt_ec ec
    
      inner_packet = create_inner_packet switch, seed, line, at
      encrypted_inner_packet = encrypt_inner_packet ec, iv, inner_packet
      outer_sig = switch.sign encrypted_inner_packet
      encrypted_sig = encrypt_signature outer_sig, ec, line, iv
      outer_packet = Telehash::Core::Packet::Raw.new({
        type: "open",
        open: Base64.encode64(encrypted_public_ec),
        iv: iv.unpack("H*")[0],
        sig: Base64.encode64(encrypted_sig)
      },
      encrypted_inner_packet)
      
      packet = outer_packet
      peer = switch.peer seed.public_key, seed.ip, seed.port
      Open.new packet, switch, peer, incoming, line, at, ec, instantiated_at
    end
    
    def to_s
      self.packet.to_s
    end
    
    def outbound?
      !self.incoming
    end
    
    protected
    
    def self.form_peer switch, srsapk, udpsocket_or_host, port = nil
      if port
        switch.peer srsapk, udpsocket_or_host, port
      else
        peeraddr = udpsocket_or_host.peeraddr false
        switch.peer srsapk, peeraddr[2], peeraddr[1]
      end
    end

    def self.parse_at inner_packet
      at = inner_packet[:at]
      unless at.is_a? Numeric
        raise ArgumentError.new '"at" value is not a numeric type'
      end
      at = Time.at at/1000.0 #milliseconds
    end

    def self.from_hex value
      [value].pack('H*')
    end
    
    def self.form_packet packet
      if packet.is_a? String
        packet = Telehash::Core::Packet::Raw.parse packet
      end
      
      unless packet[:type].eql? "open"
        raise ArgumentError.new "Packet is not an open packet"
      end
      packet
    end
    
    def initialize packet, switch, peer, incoming, line, at, ec, instantiated_at = Time.now
      @packet, @switch, @peer, @incoming, @line, @at, @ec, @instantiated_at =
        packet, switch, peer, incoming, line, at, ec, instantiated_at
    end
    
    def self.encrypt_inner_packet ec, iv, packet
      cipher = inner_packet_cipher ec, iv
      cipher.update(packet.to_s) + cipher.final
    end
    
    def self.encrypt_signature plain_sig, ec, line, iv
      cipher = encrypted_signature_cipher ec, line, iv
      cipher.padding = 1
      cipher.update(plain_sig.to_s) + cipher.final
    end

    def self.decrypt_signature encrypted_sig, ec, line, iv
      cipher = encrypted_signature_cipher ec, line, iv, false
      cipher.padding = 1
      cipher.update(Base64.decode64 encrypted_sig) + cipher.final
    end
    
    def self.ec_point_from_data sender_public_key_data
      bn = OpenSSL::BN.new(sender_public_key_data, 2)
      OpenSSL::PKey::EC::Point.new ec_group, bn
    end
    
    def self.decrypt_inner_packet ec, iv, body
      cipher = inner_packet_cipher ec, iv, false
      decrypted_body = cipher.update(body) + cipher.final
      Telehash::Core::Packet::Raw.parse decrypted_body
    end
    
    def self.inner_packet_key ec
      if ec.is_a? OpenSSL::PKey::EC
        ec_bin = ec.public_key.to_bn.to_s(2)
      elsif ec.is_a? OpenSSL::PKey::EC::Point
        ec_bin = ec.to_bn.to_s(2)
      else
        ec_bin = ec.to_s
      end
      Digest::SHA2.digest ec_bin
    end
    
    def self.encrypted_signature_key ec, line
      if ec.is_a? OpenSSL::PKey::EC
        ec_bin = ec.public_key.to_bn.to_s(2)
      elsif ec.is_a? OpenSSL::PKey::EC::Point
        ec_bin = ec.to_bn.to_s(2)
      else
        ec_bin = ec.to_s
      end
      if !line
        line = SecureRandom.hex 16
      elsif line.length == 32
        line = [line].pack("H*")
      end
      Digest::SHA2.digest(ec_bin + line)
    end
    
    def self.encrypted_signature_cipher ec, line, iv, encrypt = true
      cipher = OpenSSL::Cipher.new "AES-256-CTR"
      if encrypt
        cipher.encrypt
      else
        cipher.decrypt
      end
      if line.length == 16
        line = line.unpack('H*')[0]
      end
      
      cipher.key = encrypted_signature_key ec, line
      cipher.iv  = iv
      cipher
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

    def self.create_inner_packet switch, peer, line = nil, at = nil
      if !line
        line = SecureRandom.hex 16
      elsif line.length == 16
        line = line.unpack('H*')[0]
      end
      
      if !at
        at = Time.now
      end

      at = (at.to_f * 1000).floor
      
      Telehash::Core::Packet::Raw.new({
        to: peer.hashname,
        line: line,
        at: at
      }, switch.public_key_der)
    end
  end
end
