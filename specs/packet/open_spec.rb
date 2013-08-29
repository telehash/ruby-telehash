require 'minitest/autorun'
require 'minitest/spec'
require 'openssl'

require 'telehash'
require 'spec_helper'

module OpenSpec
  Open = Telehash::Packet::Open
  Switch = Telehash::Switch
  Seed = Telehash::Seed
  RSA = OpenSSL::PKey::RSA
  
  describe Open do
  
    let :private_key do
      data 'private_key.pem'
    end

    let :public_key do
      data 'public_key.pem'
    end

    let :switch do
      key_data = private_key + public_key
      Switch.new RSA.new(key_data, nil)
    end
  
    let :peer do
      switch.peer RSA.new(public_key), "127.0.0.1", 42424
    end
    
    it 'generates an open based on a seed' do
      seeds = Seed.parse_all data_file 'seeds.json'
      seed = seeds[0]
      open_packet = Open.generate switch, peer
      open_packet.must_be_instance_of Open
    end

    it 'parses a generated open'
  end
end
