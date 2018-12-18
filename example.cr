require "./src/blockio.cr"

require "dotenv"
Dotenv.load

client = Blockio::Client.new(ENV["API_KEY"], ENV["PIN"])

puts client.get_balance
# puts address = client.get_new_address["address"].to_s
# puts client.get_address_balance "2MtwMkQPP34274iRzvfsDpDdwSGXkRbUJWt"
puts client.withdraw({"2MtwMkQPP34274iRzvfsDpDdwSGXkRbUJWt" => BigDecimal.new(10)})
# puts client.archive_addresses([address])
# puts client.unarchive_addresses([address])

# list = client.get_my_addresses
# archive = Array(String).new
# list["addresses"].as_a.each do |x|
#   archive << x["address"].as_s if BigDecimal.new(x["available_balance"].as_s) == BigDecimal.new
# end
# puts client.archive_addresses(archive) unless archive.empty?
# puts address = client.get_new_address["address"].to_s
