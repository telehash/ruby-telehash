require 'openssl'
require 'digest'
require 'base64'
require 'securerandom'

module Telehash::Core::Packet
  class Seek
    attr_reader :channel
    attr_reader :hashname
    attr_reader :seen
    attr_reader :stream
    attr :packet
    
    def self.generate channel, hashname, seen = nil
      iv = SecureRandom.random_bytes(16)
      
      inner_packet = Telehash::Core::Packet::Raw.new({
        type: "seek",
        seek: hashname,
        c: channel.id,
        seq: 0
      })
      if seen
        inner_packet[:see] = seen.to_a
      end
      encrypted_inner_packet = channel.line.encrypt_outgoing inner_packet, iv
      packet = Telehash::Core::Packet::Raw.new({
        type: "line",
        line: channel.line.outgoing_line,
        iv: iv.unpack("H*")[0]
      }, encrypted_inner_packet)
      
      Seek.new channel, hashname, seen, packet
    end
    
    def self.parse line, packet
      if packet.is_a? String
        packet = Telehash::Core::Packet::Raw.parse packet
      end
      
      iv = packet[:iv]
      inner_packet = Telehash::Core::Packet::Raw.parse line.decrypt_incoming(packet.body, iv)

      hashname = inner_packet[:seek]
      seen = inner_packet[:see].to_a.map { |seek_line| Telehash::Core::Pointer.parse seek_line }
      Seek.new Telehash::Core::Channel.new(line, inner_packet[:c]), hashname, seen, packet
    end
    
    def to_s
      self.packet.to_s
    end
    
    protected
    def initialize channel, hashname, seen,  packet
      @channel, @hashname, @seen, @packet = channel, hashname, seen, packet
    end
  end
end
