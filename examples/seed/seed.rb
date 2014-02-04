#!/usr/bin/env ruby
require 'bundler'
require 'telehash'
require 'telehash/celluloid/switch'
require 'openssl'

Switch = Telehash::Celluloid::Switch
RSA = OpenSSL::PKey::RSA
PEMFILE = "seed.pem"
if File.exist? PEMFILE
  keypair = RSA.new File.read PEMFILE
else
  keypair = RSA.new 2048
  File.open PEMFILE, 'w' do |file|
    file.puts keypair.to_pem
    file.puts keypair.public_key.to_pem
  end
end

seeds  = Telehash::Core::Seed.parse_all File.read "./seeds.json" 
switch = Switch.new keypair
puts switch.hashname
switch.start
puts "Listening on #{switch.port}"

seeds.each do |seed|
  switch.future.open(seed)
end

sleep 2

switch.lines.each do |incoming_line_id, line|
  ch = Telehash::Core::Channel.new line
  p = Telehash::Core::Packet::Seek.generate ch, switch.hashname
  switch.send line.peer, p
end

trap("INT") { exit }

sleep
