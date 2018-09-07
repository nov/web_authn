# WebAuthn

W3C WebAuthn (a.k.a. FIDO2) RP library in Ruby

[![Build Status](https://secure.travis-ci.org/nov/web_authn.png)](http://travis-ci.org/nov/web_authn)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'web_authn'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install web_authn

## Usage

See sample code in this repository, or [working sample site](https://web-authn.herokuapp.com/).

Currently, there are several restrictions.
* only `none` attestation format is supported.
* only EC key w/ `P-(256|384|521)` public key is supported.
* authenticator data w/ extensions aren't supported.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/web_authn.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
