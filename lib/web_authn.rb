require 'active_support'
require 'active_support/core_ext'
require 'cbor'
require 'cose'
require 'cose/key/ec2'
require 'json/jwt'

module WebAuthn
  class Exception < StandardError; end
  class InvalidContext < Exception; end
  class InvalidAssertion < Exception; end
  class NotImplementedError < NotImplementedError; end

  module_function

  def context_for(encoded_client_data_json, origin:, challenge:)
    Context.for(
      encoded_client_data_json,
      origin: origin,
      challenge: challenge
    )
  end
end

require 'web_authn/attestation_object'
require 'web_authn/attested_credential_data'
require 'web_authn/authenticator_data'
require 'web_authn/client_data_json'
require 'web_authn/context'
