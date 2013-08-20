require 'minitest/autorun'
require 'minitest/spec'

require 'telehash'

Packet = Telehash::Packet

describe Packet do
  it 'can be created from just an empty hash' do
    p = Packet.new({})
    p.must_be_instance_of Packet
    p.json.must_be_instance_of Hash
    p.to_s.must_equal "\0\2{}".encode("UTF-8")
  end
  it 'can be created from an empty hash with data' do
    p = Packet.new({}, "abcd")
    p.must_be_instance_of Packet
    p.json.must_be_instance_of Hash
    p.data.must_be_instance_of String
    p.to_s.must_equal "\0\2\{}abcd".encode("UTF-8")
  end
  it 'can be created with non-empty json' do
    p = Packet.new({a: 'b'})
    p.must_be_instance_of Packet
    p.json.must_be_instance_of Hash
    p.to_s.must_equal "\0\t{\"a\":\"b\"}".encode("UTF-8")
  end
end
