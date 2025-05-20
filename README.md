# block.io has stopped operating. The code is mostly a POC and unpolished. Leaving up as archived.


# blockiocr

Crystal library to interact with block.io

Currently requires a ruby interface to handle transaction signing. Attempt to do so in crystal at `signing`

## Installation

Add this to your application's `shard.yml`:

```yaml
dependencies:
  blockiocr:
    github: greenbigfrog/blockiocr
```

## Dependencies
- Ruby (for withdrawals)

## Usage

```crystal
require "blockiocr"

client = Blockio::Client.new(ENV["API_KEY"], ENV["PIN"])

puts client.get_balance
```

If you want to withdraw coins, you'll need to run `rb/server.rb` as well

## Development

TODO: Write development instructions here

## Contributing

1. Fork it ( https://github.com/greenbigfrog/blockiocr/fork )
2. Create your feature branch (git checkout -b my-new-feature)
3. Commit your changes (git commit -am 'Add some feature')
4. Push to the branch (git push origin my-new-feature)
5. Create a new Pull Request

## Contributors

- [greenbigfrog](https://github.com/greenbigfrog) Jonathan - creator, maintainer
