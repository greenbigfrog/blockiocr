require "openssl/cipher"
require "openssl"
require "./aes"
require "bitcoinutil"

lib LibCrypto
  fun pkcs5_pbkdf2_hmac = PKCS5_PBKDF2_HMAC(pass : LibC::Char*, passlen : LibC::Int, salt : UInt8*, saltlen : LibC::Int, iter : LibC::Int, digest : EVP_MD, keylen : LibC::Int, out : UInt8*) : LibC::Int
end

module OpenSSL::PKCS5
  {% if compare_versions(LibSSL::OPENSSL_VERSION, "1.0.0") >= 0 %}
    def self.pbkdf2_hmac(secret, salt, iterations = 2**16, algorithm : OpenSSL::Algorithm = OpenSSL::Algorithm::SHA1, key_size = 64) : Bytes
      evp = algorithm.to_evp
      buffer = Bytes.new(key_size)
      if LibCrypto.pkcs5_pbkdf2_hmac(secret, secret.bytesize, salt, salt.bytesize, iterations, evp, key_size, buffer) != 1
        raise OpenSSL::Error.new "pkcs5_pbkdf2_hmac"
      end
      buffer
    end
  {% end %}
end

module OpenSSL
  enum Algorithm
    MD4
    MD5
    RIPEMD160
    SHA1
    SHA224
    SHA256
    SHA384
    SHA512

    def to_evp
      case self
      when MD4       then LibCrypto.evp_md4
      when MD5       then LibCrypto.evp_md5
      when RIPEMD160 then LibCrypto.evp_ripemd160
      when SHA1      then LibCrypto.evp_sha1
      when SHA224    then LibCrypto.evp_sha224
      when SHA256    then LibCrypto.evp_sha256
      when SHA384    then LibCrypto.evp_sha384
      when SHA512    then LibCrypto.evp_sha512
      else                raise "Invalid algorithm: #{self}"
      end
    end
  end
end

class OpenSSL::HMAC
  def self.digest(algorithm : OpenSSL::Algorithm, key, data) : Bytes
    evp = algorithm.to_evp
    key_slice = key.to_slice
    data_slice = data.to_slice
    buffer = Bytes.new(128)
    LibCrypto.hmac(evp, key_slice, key_slice.size, data_slice, data_slice.size, buffer, out buffer_len)
    buffer[0, buffer_len.to_i]
  end

  def self.hexdigest(algorithm : OpenSSL::Algorithm, key, data) : String
    digest(algorithm, key, data).hexstring
  end
end

def hash256(input : Bytes)
  hash = OpenSSL::Digest.new("SHA256")
  hash.update(input)

  hash.hexdigest
end

def hash256(string : String)
  hash256(string.to_slice)
end

def get_public_key_from_private_string(input)
  SecP256K1.pubkey_format(SecP256K1.sequence(SecP256K1::EC_GP, BigInt.new(input, 16)))
end

def sign(priv_key, data)
  rand = BigInt.new(48) # some random data
  data = hash256(hash256(data))
  a = SecP256K1.sign(BigInt.new(data, 16), BigInt.new(priv_key, 16), rand)
  puts b = a.to_s(16)

  # raise "wrong legth" unless b.size == 140

  raise "self check failed" unless verify(priv_key, a, data, rand)
  b
end

def verify(priv_key, signed_data, data, rand)
  pub_key_point = SecP256K1.sequence SecP256K1::EC_GP, BigInt.new(priv_key, 16)
  SecP256K1.verify(signed_data, BigInt.new(data, 16), pub_key_point, rand)
end

def pbkdf2(input, bytes)
  OpenSSL::PKCS5.pbkdf2_hmac(input, "test", 1024_u32, OpenSSL::Algorithm::SHA256, bytes).hexstring
end

# # Steps to a Successful Client-Side Signature
# To generate an Encryption Key from a Secret PIN, we use the following standard at Block.io:
#
# (0) Use a strong Secret PIN: e3b9760e2fef0942d9ec1116c10613f0
secret_pin = "e3b9760e2fef0942d9ec1116c10613f0"
# (1) Pass (0) through the PBKDF2 function with 128 Bit Key Length and 1,024 iterations of SHA256: 3feb1c1135bfa7db0a661b0c7999de25
key = pbkdf2(secret_pin, 16_u64)
# (2) Pass (1) through the PBKDF2 function with 256 Bit Key Length and 1,024 iterations of SHA256.
final_key = pbkdf2(key, 32_u64)

# (3) Final Encryption Key from (2): 55551019e02aa37728584c14f584132a9b63be9cd933002223b61300755803ef

# Now that we have an Encryption Key, we will use the AES-256-ECB cipher to encrypt some basic text:
# (4) Data to Encrypt: block.io
data = "block.io"
# (5) Pass (4) as data, and (3) as encryption key to AES-256-ECB cipher.
encrypted = AES.encrypt(final_key, data)
# (6) Encrypted result as a Base64 String (new lines or spaces removed): CpuJt9iUF+Om2jld4Oh8Yg==
output = Base64.encode(encrypted).chomp
# (7) Sanity check, let's decrypt the encrypted data: block.io
decrypted = AES.decrypt(final_key, encrypted)

output = "https://block.io/api/v2/verify_signature/?"
# Now let's use the decrypted data as a Private Key, and get its Public Key:
# (8) Pass (7) through SHA256 once: 7a01628988d23fae697fa05fcdae5a82fe4f749aa9f24d35d23f81bee917dfc3
priv_key = hash256(decrypted)
# (9) We use (8) as the Private Key.
# (10) Use (8) to get Public Key: 03359ac0aa241b1a40fcab68486f8a4b546ad3301d201c3645487093578592ec8f
output += "public_key=" + get_public_key_from_private_string(priv_key)
# Note: The Public Key derivation from (9) to (11) occurs through the Secp256k1 curve. You don't need to know what the details are. Instead, just use your programming language's Bitcoin or OpenSSL libraries to achieve the same result. OpenSSL supports Secp256k1 by default.
# Finally, let's sign some data. This final step puts you in control of your addresses -- you sign your transactions outside of Block.io.
# Signing of data in Dogecoin/Bitcoin/Litecoin occurs through the Secp256k1 curve. Use your language library to figure out what method signs the data. Typically, when you create a Key object, that Key object will allow you to 'sign' data.
# (11) Data to Sign: iSignedThisDataThatIs256BitsLong
data = "iSignedThisDataThatIs256BitsLong"
# (12) Convert (11) to Hex if it isn't: 695369676e65645468697344617461546861744973323536426974734c6f6e67
hex = data.to_slice.hexstring
output += "&signed_data=" + hex
# (13) Signed version of (12) using Private Key in (9): 304402205587dfc87c3227ad37b021c08c873ca4b1faada1a83f666d483711edb2f4f743022004ee40d9fe8dd03e6d42bfc7d0e53f75286125a591ed14b39265978ebf3eea36
output += "&signature=" + sign(priv_key, hex)
# (14) Use Block.io to verify signature (13) is valid for Public Key in (10): Verify Signature
# In Step (14), we used the following verify_signature API call:
# https://block.io/api/v2/verify_signature/?signed_data=695369676e65645468697344617461546861744973323536426974734c6f6e67&signature=304402205587dfc87c3227ad37b021c08c873ca4b1faada1a83f666d483711edb2f4f743022004ee40d9fe8dd03e6d42bfc7d0e53f75286125a591ed14b39265978ebf3eea36&public_key=03359ac0aa241b1a40fcab68486f8a4b546ad3301d201c3645487093578592ec8f

# https://github.com/BlockIo/gem-block-io/blob/master/lib/block_io.rb#L382-L413
puts output
