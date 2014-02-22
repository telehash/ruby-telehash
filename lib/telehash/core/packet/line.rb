module Telehash::Core::Packet
  class Line

    def self.generate line, inner_packet
      iv = SecureRandom.random_bytes(16)
      encrypted_inner_packet = line.encrypt_outgoing inner_packet, iv
      packet = Telehash::Core::Packet::Raw.new({
        type: "line",
        line: line.outgoing_line,
        iv: iv.unpack("H*")[0]
      }, encrypted_inner_packet)

      Line.new line, packet
    end

    def self.parse line, packet
      Raw = Telehash::Core::Packet::Raw
      if packet.is_a? String
        packet = Raw.parse packet
      end

      iv = packet[:iv]
      inner_packet = Raw.parse line.decrypt_incoming(packet.body, iv)

      Line.new line, packet
    end
  end
end
