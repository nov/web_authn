

```ruby
context = WebAuthn.context_for(
  client_data_json,
  origin: request.base_url,
  challenge: session[:challenge],
)
```# WebAuthn

W3C Web Authentication API (a.k.a. WebAuthN / FIDO 2.0) RP library in Ruby

[![Build Status](https://secure.travis-ci.org/nov/web_authn.png)](http://travis-ci.org/nov/web_authn)

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'web_authn'
```

And then execute:

```sh
$ bundle
```

Or install it yourself as:

```sh
$ gem install web_authn
```

## Usage

```ruby
context = WebAuthn.context_for(
  client_data_json, # NOTE: URL-safe Base64 encoded
  origin: request.base_url,
  challenge: session[:challenge],
)

if context.registration?
  context.verify!(
    attestation_object # URL-safe Base64 encoded
  )
  context.credential_id
  context.public_key # => `OpenSSL::PKey::RSA` or `OpenSSL::PKey::EC`
  context.public_cose_key # => `COSE::Key::RSA` or `COSE::Key::EC2` ref.) https://github.com/nov/cose-key
  context.sign_count # => `Integer`
elsif context.authentication?
  context.verify!(
    authenticator_data, # URL-safe Base64 encoded

    # NOTE:
    #  either 'public_key' or 'public_cose_key' is required.
    #  if `public_key` is given, you can also specify `digest` (default: `OpenSSL::Digest::SHA256.new`).
    #  if `public_cose_key` is given, it includes digest size information, so no `digest` is required.

    # public_key: public_key, # `OpenSSL::PKey::RSA` or `OpenSSL::PKey::EC`
    # digest: OpenSSL::Digest::SHA256.new, # `OpenSSL::Digest::SHA(1|256|384|512)`` (default: `OpenSSL::Digest::SHA256`)
    public_cose_key: public_cose_key, # `COSE::Key::RSA` or `COSE::Key::EC` ref.) https://github.com/nov/cose-key

    sign_count: previously_stored_sign_count,
    signature: signature # URL-safe Base64 encoded
  )
  context.sign_count # => Integer
else
  # should never happen.
end
```

See sample code in this repository, or [working sample site](https://web-authn.herokuapp.com/).

Currently, there are several restrictions.
* only `none` attestation format is supported.
* only EC key w/ `P-(256|384|521)` public key is supported.
* authenticator data w/ extensions aren't supported.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `VERSION`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/nov/web_authn.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
