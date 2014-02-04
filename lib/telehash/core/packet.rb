require 'telehash/core/packet/raw'
require 'telehash/core/packet/open'
require 'telehash/core/packet/seek'

module Telehash::Core
  module Packet
    def self.parse switch, packetdata, addrinfo
      peer = switch.peer_from_addrinfo addrinfo
      raw = Telehash::Core::Packet::Raw.parse packetdata
      type = raw["type"]
      case type
      when "open"
        return Open.parse switch, raw, addrinfo[2], addrinfo[1]
      when "line"
        line = switch.lines[raw["line"]]
        if line
          return Seek.parse line, raw
        else
          puts "unknown line received, disposing"
        end
      else
        puts "unknown packet type: #{type}"
      end
    end
  end
end
