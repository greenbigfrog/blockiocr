require "openssl/cipher"

module AES
  def self.encrypt(password, data)
    cipher = OpenSSL::Cipher.new("aes-256-ecb")
    cipher.encrypt
    cipher.key = password
    io = IO::Memory.new
    io.write(cipher.update(data))
    io.write(cipher.final)
    io.to_slice
  end

  def self.decrypt(password, data)
    cipher = OpenSSL::Cipher.new("aes-256-ecb")
    cipher.decrypt
    cipher.key = password
    io = IO::Memory.new
    io.write(cipher.update(data))
    io.write(cipher.final)
    io.to_s
  end
end
