require "http/client"
require "json"

class Helper
  def initialize(@api_key : String, @api_base : String = "https://block.io/api/v2/")
  end

  def rest(link : String)
    res = HTTP::Client.post link
    JSON.parse(res.body)
  end

  def get(endpoint : String, *args)
    args = args.join('&')
    args = '&' + args unless args.empty?

    url = @api_base + endpoint + "?api_key=#{@api_key}" + args
    res = self.rest(url)
    data = res["data"]
    raise "Error for URL: #{url}: #{data["error_message"]}" unless res["status"] == "success"
    data
  end
end
