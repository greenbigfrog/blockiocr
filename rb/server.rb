require 'sinatra'
require 'json'
require './block_io'

post '/sign' do
  data = JSON.parse request.body.read

  encrypted_passphrase = data['data']['encrypted_passphrase']['passphrase']

  # let's get our private key
  key = Helper.extractKey(encrypted_passphrase, Helper.pinToAesKey(data['pin']))

  raise Exception, 'Public key mismatch for requested signer and ourselves. Invalid Secret PIN detected.' if key.public_key != data['data']['encrypted_passphrase']['signer_public_key']

  # let's sign all the inputs we can
  inputs = data['data']['inputs']

  Helper.signData(inputs, [key])

  content_type :json
  JSON.generate(data['data'])
end
