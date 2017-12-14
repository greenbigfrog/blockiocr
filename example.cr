require "./src/blockio.cr"

require "dotenv"
Dotenv.load

client = Blockio::Client.new(ENV["API_KEY"])

puts client.get_balance
puts client.get_new_address
