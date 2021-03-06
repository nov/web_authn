module WebAuthn
  class Context
    attr_accessor :client_data_json

    def initialize(client_data_json)
      self.client_data_json = client_data_json
    end

    def verify_session!(origin:, challenge:)
      if client_data_json.origin != origin
        raise InvalidContext, 'Invalid Origin'
      end
      if client_data_json.challenge != challenge
        raise InvalidContext, 'Invalid Challenge'
      end
      self
    end

    def registration?
      false
    end

    def authentication?
      false
    end

    def verify_flags!
      unless flags.uv? || flags.up?
        raise InvalidAssertion, 'Missing Flag: uv" nor "up"'
      end
    end

    class << self
      def for(encoded_client_data_json, origin:, challenge:)
        client_data_json = ClientDataJSON.decode encoded_client_data_json

        context = case client_data_json.type
        when 'webauthn.create'
          Registration.new(client_data_json)
        when 'webauthn.get'
          Authentication.new(client_data_json)
        else
          raise InvalidContext, 'Unknown Client Data JSON Type'
        end

        context.verify_session!(origin: origin, challenge: challenge)
      end
    end
  end
end

require 'web_authn/context/authentication'
require 'web_authn/context/registration'
