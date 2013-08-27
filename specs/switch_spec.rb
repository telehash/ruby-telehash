require 'minitest/autorun'
require 'minitest/spec'

require 'telehash'
require 'spec_helper'
require 'byebug'

module SwitchSpec
  Switch = Telehash::Switch
  RSA = OpenSSL::PKey::RSA
  Seed = Telehash::Seed

  describe Switch do
    let :private_key do
      data 'private_key.pem'
    end
  
    let :public_key do
      data 'public_key.pem'
    end
  
    subject do
      key_data = private_key + public_key
      Switch.new RSA.new(key_data, nil)
    end

    it 'is created with an RSA keypair' do
      pkey   = RSA.generate 1024
      switch = Switch.new pkey
      switch.must_be_instance_of Switch
      switch.public_key.to_text.must_equal pkey.public_key.to_text
    end
  
    it 'correctly generates a hashname' do
      subject.hashname.must_equal '433b00ac57829581068051e868d5c11cbee4a326611a8640a3175442e68976dd'
    end
  
    it 'generates an open based on a seed' do
      seeds = Seed.parse_all data_file 'seeds.json'
      seed = seeds[0]
      open_packet = subject.generate_open seed
      open_packet.must_be_instance_of Packet
    end
  
    it 'parses a generated open'
  end
end
