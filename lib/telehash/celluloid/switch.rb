require 'celluloid/io'

# TODO hashname, ip, port, - public ip, public port?
# whois(hashname) -> Hashname
#     Hashname.start(type, args)
#     type - type of channel (seek, connect, peer)
#     four additional channel types - single, msg, packet, stream, bulk
#     single - lossy req-resp 
#     msg - durable, in order messages
#     packet - non-durable, in order
#     stream - durable, in order stream of data (tcp socket)
#     bulk - wrapper around stream for large objects
module Telehash::Celluloid
  class Switch < Telehash::Core::Switch
    
    include Celluloid::IO
    
    attr_reader :listening_ip, :port
    attr_reader :lines, :peer_lines
    attr :socket, :dht
    attr :pending_opens

    def initialize rsa_pkey, listening_ip: 0, port: 0
      @listening_ip, @port = listening_ip, port
      super rsa_pkey
      @dht = Telehash::Core::DHT.new self.hashname
      @pending_opens = []
      @lines = {}
      @peer_lines = {}
    end

    def open peer
      packet = Telehash::Core::Packet::Open.generate self, peer
      pending_opens << packet
      @socket.send packet.to_s, 0, peer.ip.to_s, peer.port
    end
    
    def send peer, packet
      @socket.send packet.to_s, 0, peer.ip.to_s, peer.port
    end
    
    def start
      @socket = UDPSocket.new
      @socket.bind @listening_ip, @port
      async.run
    end

    private 
    
    def run
      loop { async.process_packet *(@socket.recvfrom 65536) }
    end
    
    def process_packet packet, addrinfo
      puts "received packet"
      packet = Telehash::Core::Packet.parse self, packet, addrinfo
      puts "parsed packet"

      case packet
      when Telehash::Core::Packet::Open
        puts "received open"
        puts "checking #{pending_opens.length} pending_open(s)"
        outbound = pending_opens.find do |pending|
          packet.peer.eql?(pending.peer) && pending.outbound?
        end
        puts "pending = #{outbound}"
        if outbound
          line = Telehash::Core::Line.new packet, outbound
          @peer_lines[line.peer.hashname] = line
          @lines[line.incoming_line] = line
        end
      when Telehash::Core::Packet::Seek
        puts "received seek"
      end
    end
  end
end
