require 'active_support'
require 'active_support/core_ext'

module WebAuthn
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
