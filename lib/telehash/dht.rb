module Telehash
  # DHT support data structure
	class DHT
    attr_reader :k, :kbuckets, :hashvalue, :pending

    KEY_SIZE = 256
    BUCKETS = KEY_SIZE / 8
    
    def initialize my_hash, k = 20
      @hashvalue  = DHT.as_bn my_hash
      @k = k
      @kbuckets = Array.new(BUCKETS) { Array.new }
      @pending  = []
    end
    
    def hashname
      @hashname ||= @hashalue.to_s(16).rjust(64, '0')
    end
    
    def self.distance x, y
      x_bn = as_bn x
      y_bn = as_bn y
      x_bn ^ y_bn
    end
    
    def self.magnitude distance
      mag = Math.log2(as_bn distance)
      return mag == (-Float::INFINITY) ? nil : mag.to_i
    end
    
    def self.as_bn key
      if key.is_a? String
        if key.length == 64
          key = key.to_i 16 # convert from hex
        else
          key.bytes.inject(0) { |a, b| (a << 8) + b } # convert from binary
        end
      else
        key # assume is already a proper numeric value
      end
    end
    def add_key key
      key = DHT.as_bn key
      index = compute_index key
      if index
        bucket = @kbuckets[index]
      
        pos = bucket.find_index key

        if pos
          # move to end, most recently seen
          bucket.delete_at pos
          bucket << key
        elsif bucket.length < @k
          bucket << key
        elsif pending.length < @k
          pending << key
        end
      end
    end
    
    # grab all values from the correct bucket, then if we still want/need more,
    # grab from the surrounding buckets
    def find_nearest key, max_results = @k
      key = DHT.as_bn key
      index = compute_index(key) || 0
      results = []
      max_offset = [index, BUCKETS - index].max
      
      0.upto max_offset do |offset|

        if index + offset < BUCKETS
          results += @kbuckets[index + offset]
        end

        if offset != 0
          if index - offset >= 0
            results += @kbuckets[index - offset]
          end
        end

        break if results.length >= max_results
      end
      results[0...@k]
    end
    
    def compute_index key
      mag = DHT.magnitude(DHT.distance @hashvalue, key)
      mag ? mag / 8 : nil
    end
	end
end