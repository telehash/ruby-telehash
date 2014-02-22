require 'telehash/core/packet/raw'
require 'telehash/core/packet/line_packet'
require 'telehash/core/packet/open_packet'
require 'telehash/core/packet/seek_packet'

module Telehash::Core
  module Packet
    def self.parse switch, packetdata, addrinfo
      peer = switch.peer_from_addrinfo addrinfo
      raw = Telehash::Core::Packet::Raw.parse packetdata
      type = raw["type"]
      case type
      when "open"
        return OpenPacket.parse switch, raw, addrinfo[2], addrinfo[1]
      when "line"
        line = switch.lines[raw["line"]]
        if line
          return SeekPacket.parse line, raw
        else
          puts "unknown line received, disposing"
        end
      else
        puts "unknown packet type: #{type}"
      end
    end
  end
end
