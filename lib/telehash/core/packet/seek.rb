require 'openssl'
require 'digest'
require 'base64'
require 'securerandom'

module Telehash::Core::Packet
  class Seek
    attr_reader :line
    attr_reader :hashname
    attr_reader :seen
    attr_reader :stream
    attr :packet
    
    def self.generate line, hashname, seen = nil
      iv = SecureRandom.random_bytes(16)
      stream = SecureRandom.hex(16)
      
      inner_packet = Telehash::Core::RawPacket.new({
        type: "seek",
        seek: hashname,
        stream: stream,
        seq: 0
      })
      if seen
        inner_packet[:see] = seen.to_a
      end
      encrypted_inner_packet = line.encrypt_outgoing inner_packet, iv
      packet = Telehash::Core::RawPacket.new({
        type: "line",
        line: line.outgoing_line,
        iv: iv.unpack("H*")[0]
      }, encrypted_inner_packet)
      
      Seek.new line, hashname, seen, stream, packet
    end
    
    def self.parse line, packet
      if packet.is_a? String
        packet = Telehash::Core::RawPacket.parse packet
      end
      
      iv = packet[:iv]
      inner_packet = Telehash::Core::RawPacket.parse line.decrypt_incoming(packet.data, iv)

      hashname = inner_packet[:seek]
      seen = inner_packet[:see].to_a.map { |seek_line| Telehash::Core::Pointer.parse seek_line }
      Seek.new line, hashname, seen, inner_packet[:stream], packet
      inner_packet = Telehash::Core::RawPacket.parse line.decrypt_incoming(packet.data, iv)

    end
    
    def to_s
      self.packet.to_s
    end
    
    protected
    def initialize line, hashname, seen, stream, packet
      @line, @hashname, @seen, @stream, @packet = line, hashname, seen, stream, packet
    end
  end
end
