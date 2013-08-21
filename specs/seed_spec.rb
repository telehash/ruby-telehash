require 'minitest/autorun'
require 'minitest/spec'

require 'telehash'

Seed = Telehash::Seed

describe Seed do
  describe 'creation' do
    let :private_key do
      File.read(File.dirname(__FILE__) + '/data/private-key.pem')
    end
  
    let :public_key do
      File.read(File.dirname(__FILE__) + '/data/public-key.pem')
    end
  
    let :switch do
      key_data = private_key + public_key
      Switch.new RSA.new(key_data, nil)
    end
    
    it 'can be created from JSON string' do
      s = Seed.new <<-END_JSON
      {
        "ip" : "127.0.0.1",
        "port": 42424,
        "hashname": "#{switch.hashname}",
        "pubkey": "#{switch.public_key.to_pem.gsub(/\n/, '\n')}"
      }
      END_JSON
      
      s.must_be_instance_of Seed
      s.ip.must_equal IPAddr.new "127.0.0.1"
      s.port.must_equal 42424
      s.hashname.must_equal switch.hashname
      s.public_key.to_der.must_equal switch.public_key.to_der
    end
    
    it 'can parse a JSON file for multiple seeds' do
      seeds = Seed.parse_all File.read(File.dirname(__FILE__) + "/data/seeds.json")
      seeds.must_be_instance_of Array
      seeds.size.must_equal 1
      s = seeds[0]
      s.hashname.must_equal "5fa6f146d784c9ae6f6d762fbc56761d472f3d097dfba3915c890eec9b79a088"
    end
  end
end
