module Blockio
  class Client
    def initialize(@api_key : String)
      @help = Helper.new(@api_key)
    end

    # Returns a newly generated address, and its unique(!) label generated by Block.io. You can optionally specify a custom label.
    def get_new_address(label : String = "")
      label = "&label=#{label}" unless label.empty?

      @help.get(endpoint: "get_new_address", data: label)
    end

    # Returns the balance of your entire Bitcoin, Litecoin, or Dogecoin account (i.e., the sum of balances of all addresses/users within it) as numbers to 8 decimal points, as strings.
    def get_balance
      @help.get("get_balance")
    end
  end
end
