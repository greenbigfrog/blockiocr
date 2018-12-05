require "./src/blockio.cr"

require "dotenv"
Dotenv.load

client = Blockio::Client.new(ENV["API_KEY"])

# puts client.get_balance
a = client.get_new_address["address"].to_s
# puts client.get_my_addresses
# puts client.get_my_addresses_without_balances
# puts client.get_address_balance "2MtwMkQPP34274iRzvfsDpDdwSGXkRbUJWt"
# puts client.get_address_by_label "stizo34"
pp client.withdraw(a, BigDecimal.new(10))
