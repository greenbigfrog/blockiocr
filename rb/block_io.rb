class Key
  require 'ecdsa'
  def initialize(privkey = nil, compressed = true)
    # the privkey must be in hex if at all provided

    @group = ECDSA::Group::Secp256k1
    @private_key = privkey.to_i(16) || 1 + SecureRandom.random_number(group.order - 1)
    @public_key = @group.generator.multiply_by_scalar(@private_key)
    @compressed = compressed
  end

  def private_key
    # returns private key in hex form
    @private_key.to_s(16)
  end

  def public_key
    # returns the compressed form of the public key to save network fees (shorter scripts)

    ECDSA::Format::PointOctetString.encode(@public_key, compression: @compressed).unpack('H*')[0]
  end

  def sign(data)
    # signed the given hexadecimal string

    nonce = deterministicGenerateK([data].pack('H*'), @private_key) # RFC6979

    signature = ECDSA.sign(@group, @private_key, data.to_i(16), nonce)

    # BIP0062 -- use lower S values only
    r, s = signature.components

    over_two = @group.order >> 1 # half of what it was
    s = @group.order - s if s > over_two

    signature = ECDSA::Signature.new(r, s)

    # DER encode this, and return it in hex form
    ECDSA::Format::SignatureDerString.encode(signature).unpack('H*')[0]
  end

  def self.from_passphrase(passphrase)
    # create a private+public key pair from a given passphrase
    # think of this as your brain wallet. be very sure to use a sufficiently long passphrase
    # if you don't want a passphrase, just use Key.new and it will generate a random key for you

    raise Exception, 'Must provide passphrase at least 8 characters long.' if passphrase.nil? || (passphrase.length < 8)

    hashed_key = Helper.sha256([passphrase].pack('H*')) # must pass bytes to sha256

    Key.new(hashed_key)
  end

  def self.from_wif(wif)
    # returns a new key extracted from the Wallet Import Format provided
    # TODO check against checksum

    hexkey = Helper.decode_base58(wif)
    actual_key = hexkey[2...66]

    (compressed = hexkey[2..hexkey.length].length - 8 > 64) && (hexkey[2..hexkey.length][64...66] == '01')

    Key.new(actual_key, compressed)
  end

  def isPositive(i)
    sig = '!+-'[i <=> 0]

    sig.eql?('+')
  end

  def deterministicGenerateK(data, privkey, group = ECDSA::Group::Secp256k1)
    # returns a deterministic K  -- RFC6979

    hash = data.bytes.to_a

    x = [privkey.to_s(16)].pack('H*').bytes.to_a

    k = []
    32.times { k.insert(0, 0) }

    v = []
    32.times { v.insert(0, 1) }

    # step D
    k = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k.pack('C*'), [].concat(v).concat([0]).concat(x).concat(hash).pack('C*')).bytes.to_a

    # step E
    v = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k.pack('C*'), v.pack('C*')).bytes.to_a

    #  puts "E: " + v.pack("C*").unpack("H*")[0]

    # step F
    k = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k.pack('C*'), [].concat(v).concat([1]).concat(x).concat(hash).pack('C*')).bytes.to_a

    # step G
    v = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k.pack('C*'), v.pack('C*')).bytes.to_a

    # step H2b (Step H1/H2a ignored)
    v = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k.pack('C*'), v.pack('C*')).bytes.to_a

    h2b = v.pack('C*').unpack('H*')[0]
    tNum = h2b.to_i(16)

    # step H3
    while !isPositive(tNum) || (tNum >= group.order)
      # k = crypto.HmacSHA256(Buffer.concat([v, new Buffer([0])]), k)
      k = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k.pack('C*'), [].concat(v).concat([0]).pack('C*')).bytes.to_a

      # v = crypto.HmacSHA256(v, k)
      v = OpenSSL::HMAC.digest(OpenSSL::Digest.new('sha256'), k.pack('C*'), v.pack('C*')).bytes.to_a

      # T = BigInteger.fromBuffer(v)
      tNum = v.pack('C*').unpack('H*')[0].to_i(16)
    end

    tNum
  end
  end

module Helper
  require 'pbkdf2'
  require 'base64'

  def self.signData(inputs, keys)
    # sign the given data with the given keys
    # TODO loop is O(n^3), make it better

    raise Exception, 'Keys object must be an array of keys, without at least one key inside it.' unless keys.is_a?(Array) && (keys.size >= 1)

    i = 0
    while i < inputs.size
      # iterate over all signers
      input = inputs[i]

      j = 0
      while j < input['signers'].size
        # if our public key matches this signer's public key, sign the data
        signer = inputs[i]['signers'][j]

        k = 0
        while k < keys.size
          # sign for each key provided, if we can
          key = keys[k]
          signer['signed_data'] = key.sign(input['data_to_sign']) if signer['signer_public_key'] == key.public_key
          k += 1
        end

        j += 1
      end

      i += 1
    end

    inputs
  end

  def self.extractKey(encrypted_data, b64_enc_key)
    # passphrase is in plain text
    # encrypted_data is in base64, as it was stored on Block.io
    # returns the private key extracted from the given encrypted data

    decrypted = decrypt(encrypted_data, b64_enc_key)

    Key.from_passphrase(decrypted)
  end

  def self.sha256(value)
    # returns the hex of the hash of the given value
    hash = Digest::SHA2.new(256)
    hash << value
    hash.hexdigest # return hex
  end

  def self.pinToAesKey(secret_pin, iterations = 2048)
    # converts the pincode string to PBKDF2
    # returns a base64 version of PBKDF2 pincode
    salt = ''

    # pbkdf2-ruby gem uses SHA256 as the default hash function
    aes_key_bin = PBKDF2.new(password: secret_pin, salt: salt, iterations: iterations / 2, key_length: 128 / 8).value
    aes_key_bin = PBKDF2.new(password: aes_key_bin.unpack('H*')[0], salt: salt, iterations: iterations / 2, key_length: 256 / 8).value

    Base64.strict_encode64(aes_key_bin) # the base64 encryption key
  end

  # Decrypts a block of data (encrypted_data) given an encryption key
  def self.decrypt(encrypted_data, b64_enc_key, iv = nil, cipher_type = 'AES-256-ECB')
    response = nil

    begin
      aes = OpenSSL::Cipher.new(cipher_type)
      aes.decrypt
      aes.key = Base64.strict_decode64(b64_enc_key)
      aes.iv = iv unless iv.nil?
      response = aes.update(Base64.strict_decode64(encrypted_data)) + aes.final
    rescue Exception => e
      # decryption failed, must be an invalid Secret PIN
      raise Exception, 'Invalid Secret PIN provided.'
    end

    response
  end

  # Encrypts a block of data given an encryption key
  def self.encrypt(data, b64_enc_key, iv = nil, cipher_type = 'AES-256-ECB')
    aes = OpenSSL::Cipher.new(cipher_type)
    aes.encrypt
    aes.key = Base64.strict_decode64(b64_enc_key)
    aes.iv = iv unless iv.nil?
    Base64.strict_encode64(aes.update(data) + aes.final)
  end

  # courtesy bitcoin-ruby

  def self.int_to_base58(int_val, _leading_zero_bytes = 0)
    alpha = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    base58_val = ''
    base = alpha.size
    while int_val > 0
      int_val, remainder = int_val.divmod(base)
      base58_val = alpha[remainder] + base58_val
    end
    base58_val
  end

  def self.base58_to_int(base58_val)
    alpha = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
    int_val = 0
    base = alpha.size
    base58_val.reverse.each_char.with_index do |char, index|
      raise ArgumentError, 'Value not a valid Base58 String.' unless char_index = alpha.index(char)

      int_val += char_index * (base**index)
    end
    int_val
  end

  def self.encode_base58(hex)
    leading_zero_bytes = (hex =~ /^([0]+)/ ? Regexp.last_match(1) : '').size / 2
    ('1' * leading_zero_bytes) + Helper.int_to_base58(hex.to_i(16))
  end

  def self.decode_base58(base58_val)
    s = Helper.base58_to_int(base58_val).to_s(16); s = (s.bytesize.odd? ? '0' + s : s)
    s = '' if s == '00'
    leading_zero_bytes = (base58_val =~ /^([1]+)/ ? Regexp.last_match(1) : '').size
    s = ('00' * leading_zero_bytes) + s if leading_zero_bytes > 0
    s
  end
end
