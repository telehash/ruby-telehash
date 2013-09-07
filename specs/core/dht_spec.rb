require 'minitest/autorun'
require 'minitest/spec'

require 'telehash'

module DHTSpec
  DHT = Telehash::Core::DHT
  describe DHT do
    subject do
      DHT.new 0, 1
    end
    describe '#initialize' do
      it 'can be created from a hex hash' do
       dht = DHT.new('0' * 64)
       dht.hashvalue.must_equal 0
      end
      it 'can be created from a binary' do
        dht = DHT.new("\x0" * 32)
        dht.hashvalue.must_equal 0
      end
      it 'can be created from an integer' do
        dht = DHT.new(1 << 255)
        dht.hashvalue.must_equal(1 << 255)
      end
      
      it 'can be created with a smaller `k` value' do
        subject.k.must_equal 1
      end
    end
    
    describe '#as_bn' do
      it 'can deal with hex hash' do
        DHT.as_bn('f' * 64).must_equal (1 << 256) - 1
      end

      it 'can deal with binary' do
        DHT.as_bn("\xff" * 32).must_equal((1 << 256) - 1)
      end

      it 'can deal ith hex hash' do
        DHT.as_bn(1 << 254).must_equal 1 << 254
      end
    end
    
    describe '#distance' do
      it 'can compute distance between two numbers' do
        DHT.distance(0x1234, 0x4321).must_equal 0x5115
      end
    end
    
    describe '#magnitude' do
      it 'can compute magnitude of distance between two numbers' do
        DHT.magnitude(0x5115).must_equal 14
      end

      it 'can deal with magnitude of zero by returning nil' do
        DHT.magnitude(0).must_be_nil
      end
    end
    
    describe '#add_key' do
      it 'can add a key' do
        subject.add_key '1' * 64
        subject.find_nearest('1' * 64).must_include DHT.as_bn '1' * 64
      end

      it 'doesnt let my key be added' do
        subject.add_key subject.hashvalue
        subject.find_nearest(0).wont_include subject.hashvalue
      end

      it 'can deal with an overflow in the `k` bucket' do
        subject.add_key '1' * 64
        subject.add_key '2' * 64
        subject.find_nearest('2' * 64).wont_include DHT.as_bn '2' * 64
        subject.pending.must_include DHT.as_bn '2' * 64
      end
      
      it 'ignores keys if pending is full' do
        subject.add_key '1' * 64
        subject.add_key '2' * 64
        subject.add_key '3' * 64
        subject.find_nearest('3' * 64).wont_include '3' * 64
        subject.pending.wont_include '3' * 64
      end
    end
  end
end