## Steps to a Successful Client-Side Signature
# To generate an Encryption Key from a Secret PIN, we use the following standard at Block.io:
# 
# (0) Use a strong Secret PIN: e3b9760e2fef0942d9ec1116c10613f0
# (1) Pass (0) through the PBKDF2 function with 128 Bit Key Length and 1,024 iterations of SHA256: 3feb1c1135bfa7db0a661b0c7999de25
# (2) Pass (1) through the PBKDF2 function with 256 Bit Key Length and 1,024 iterations of SHA256.
# (3) Final Encryption Key from (2): 55551019e02aa37728584c14f584132a9b63be9cd933002223b61300755803ef
# Now that we have an Encryption Key, we will use the AES-256-ECB cipher to encrypt some basic text:
# 
# (4) Data to Encrypt: block.io
# (5) Pass (4) as data, and (3) as encryption key to AES-256-ECB cipher.
# (6) Encrypted result as a Base64 String (new lines or spaces removed): CpuJt9iUF+Om2jld4Oh8Yg==
# (7) Sanity check, let's decrypt the encrypted data: block.io
# Now let's use the decrypted data as a Private Key, and get its Public Key:
# 
# (8) Pass (7) through SHA256 once: 7a01628988d23fae697fa05fcdae5a82fe4f749aa9f24d35d23f81bee917dfc3
# (9) We use (8) as the Private Key.
# (10) Use (8) to get Public Key: 03359ac0aa241b1a40fcab68486f8a4b546ad3301d201c3645487093578592ec8f
# Note: The Public Key derivation from (9) to (11) occurs through the Secp256k1 curve. You don't need to know what the details are. Instead, just use your programming language's Bitcoin or OpenSSL libraries to achieve the same result. OpenSSL supports Secp256k1 by default.
# Finally, let's sign some data. This final step puts you in control of your addresses -- you sign your transactions outside of Block.io.
#
# Signing of data in Dogecoin/Bitcoin/Litecoin occurs through the Secp256k1 curve. Use your language library to figure out what method signs the data. Typically, when you create a Key object, that Key object will allow you to 'sign' data.
# (11) Data to Sign: iSignedThisDataThatIs256BitsLong
# (12) Convert (11) to Hex if it isn't: 695369676e65645468697344617461546861744973323536426974734c6f6e67
# (13) Signed version of (12) using Private Key in (9): 304402205587dfc87c3227ad37b021c08c873ca4b1faada1a83f666d483711edb2f4f743022004ee40d9fe8dd03e6d42bfc7d0e53f75286125a591ed14b39265978ebf3eea36
# (14) Use Block.io to verify signature (13) is valid for Public Key in (10): Verify Signature
# In Step (14), we used the following verify_signature API call:
# https://block.io/api/v2/verify_signature/?signed_data=695369676e65645468697344617461546861744973323536426974734c6f6e67&signature=304402205587dfc87c3227ad37b021c08c873ca4b1faada1a83f666d483711edb2f4f743022004ee40d9fe8dd03e6d42bfc7d0e53f75286125a591ed14b39265978ebf3eea36&public_key=03359ac0aa241b1a40fcab68486f8a4b546ad3301d201c3645487093578592ec8f
