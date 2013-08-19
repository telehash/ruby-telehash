require 'digest'

module Telehash
  class Switch
    attr_reader :public_key
    attr        :hashname
    
    def initialize(rsa_pkey)
      @key            = rsa_pkey.dup
      @public_key     = rsa_pkey.public_key
      @public_key_pem = rsa_pkey.public_key.to_pem.freeze
    end
    
    def hashname
      @hashname ||= Digest::SHA2.hexdigest @public_key_pem
    end
  end
end
