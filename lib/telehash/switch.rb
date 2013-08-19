require 'digest'

module Telehash
  class Switch
    attr_reader :public_key
    attr_reader :network
    attr :hashname
    
    def initialize(rsa_pkey, network)
      @key = rsa_pkey.dup
      @public_key = rsa_pkey.public_key
      @network = network.dup.freeze
      @public_key_pem = rsa_pkey.public_key.to_pem.freeze
    end
    
    def hashname
      @hashname ||= Digest::SHA2.hexdigest @public_key_pem
    end
  end
end
