require "http/client"
require "json"

class Helper
  def initialize(@api_key : String, @api_base : String = "https://block.io/api/v2/")
  end

  def rest(link : String)
    res = HTTP::Client.get link
    JSON.parse(res.body)
  end

  def get(endpoint : String, data : String = "")
    data = "&#{data}" unless data.empty?
    res = self.rest(@api_base + endpoint + "?api_key=#{@api_key}" + data)
    data = res["data"]
    raise "Error: #{data["error_message"]}" unless res["status"] == "success"
    data
  end
end
