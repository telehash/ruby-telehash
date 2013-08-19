require 'minitest/autorun'
require 'minitest/spec'

require 'telehash'

Switch = Telehash::Switch
RSA = OpenSSL::PKey::RSA

describe Switch do
  let :private_key do
    File.read(File.dirname(__FILE__) + '/data/private-key.pem')
  end
  
  let :public_key do
    File.read(File.dirname(__FILE__) + '/data/public-key.pem')
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
    subject.hashname.must_equal 'bd9954ac199993a41d928345e7d331d9bd07473a511c080febf168367ca27c78'
  end
end
