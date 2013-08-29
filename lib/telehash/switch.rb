require 'digest'
require 'base64'
require 'openssl'
require 'securerandom'
require 'telehash/peer'
require 'telehash/raw_packet'

module Telehash
  class Switch
    attr_reader :public_key
    attr        :hashname
    
    def initialize(rsa_pkey)
      @key            = rsa_pkey
      @public_key     = rsa_pkey.public_key
      @public_key_der = rsa_pkey.public_key.to_der.freeze
      @pending_lines  = {} #hashname to EC key
    end
    
    def hashname
      @hashname ||= Digest::SHA2.hexdigest @public_key_der
    end

    def ec_group
      group = OpenSSL::PKey::EC::Group.new "prime256v1"
      group.point_conversion_form = :uncompressed
      group
    end

    def generate_ec 
      ec = OpenSSL::PKey::EC.new ec_group
      ec.generate_key
    end
    
    def sign_with_sha2_pss data
      hash = Digest::SHA2.digest data
      @key.private_encrypt 
    end

    def create_inner_packet seed, line, at = nil
      if !line
        line = SecureRandom.hex 16
      elsif line.length == 16
        line = line.unpack('H*')[0]
      end
      
      if !at
        at = Time.now
      end

      if at.is_a? Time
        at = (at.to_f * 1000).floor
      end
      
      RawPacket.new({
        to: seed.hashname,
        line: line,
        at: at
      }, @public_key_der)
    end

    def inner_packet_key ec
      if ec.is_a? OpenSSL::PKey::EC
        ec_bin = ec.public_key.to_bn.to_s(2)
      elsif ec.is_a? OpenSSL::PKey::EC::Point
        ec_bin = ec.to_bn.to_s(2)
      else
        ec_bin = ec.to_s
      end
      key    = Digest::SHA2.digest ec_bin
    end
    
    def inner_packet_cipher ec, iv, encrypt = true
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

    def encrypt_inner_packet ec, iv, packet
      cipher = inner_packet_cipher ec, iv
      cipher.update(packet.to_s) + cipher.final
    end

    def decrypt_inner_packet ec, iv, data
      cipher = inner_packet_cipher ec, iv, false
      decrypted_data = cipher.update(data) + cipher.final
      RawPacket.parse decrypted_data
    end
    
    def generate_open peer, family = nil
      unless peer.public_key
        raise ArgumentError.new "Peer does not have a public key"
      end
      
      iv   = SecureRandom.random_bytes 16
      line = SecureRandom.random_bytes 16
      ec   = generate_ec

      encrypted_public_ec = peer.encrypt_ec ec
      
      inner_packet = create_inner_packet peer, line
      encrypted_inner_packet = encrypt_inner_packet ec, iv, inner_packet
      outer_sig = @key.sign(OpenSSL::Digest::SHA256.new, encrypted_inner_packet)

      outer_packet = RawPacket.new({
        type: "open",
        open: Base64.encode64(encrypted_public_ec),
        iv: iv.unpack("H*")[0],
        sig: Base64.encode64(outer_sig)
      },
      encrypted_inner_packet)
      
      if family
        outer_packet.json["family"] = family.to_s
      end
      outer_packet
    end
    
    def parse_open packet
      if packet.is_a? String
        packet = RawPacket.parse packet
      end
      unless packet["type"].eql? "open"
        raise ArgumentError.new "Packet is not an open packet"
      end
      
      open = packet["open"]
      sender_ec_public_key_data = @key.private_decrypt(Base64.decode64(open), OpenSSL::PKey::RSA::PKCS1_OAEP_PADDING)
      secpk = ec_point_from_data sender_ec_public_key_data

      inner_packet = decrypt_inner_packet secpk, [packet["iv"]].pack("H*"), packet.data
      
      unless inner_packet["to"].eql? self.hashname
        raise ArgumentError.new "Packet was not meant for my hashname"
      end
      
      # TODO verify 'at' timestamp
      # TODO capture 'line'
      
      sender_rsa_public_key_data = inner_packet.data
      sender_hashname = Digest::SHA2.hexdigest sender_rsa_public_key_data
      srsapk = OpenSSL::PKey::RSA.new sender_rsa_public_key_data

      unless srsapk.verify(OpenSSL::Digest::SHA256.new, Base64.decode64(packet["sig"]), packet.data)
        raise ArgumentError.new "Inner packet was not signed by the sender's RSA public key"
      end
      
      # TODO derive line key
    end
    
    def ec_point_from_data sender_public_key_data
      bn = OpenSSL::BN.new(sender_public_key_data, 2)
      OpenSSL::PKey::EC::Point.new ec_group, bn
    end
    
    def to_s
      "Switch: hashname: #{self.hashname}"
    end
  end
end
