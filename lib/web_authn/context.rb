module WebAuthn
  class Context
    attr_accessor :client_data_json

    def initialize(client_data_json)
      self.client_data_json = client_data_json
    end

    def verify_session!(origin:, challenge:)
      raise 'Invalid Client Data JSON Origin' unless client_data_json.origin == origin
      raise 'Invalid Client Data JSON Session' unless client_data_json.challenge == challenge
      self
    end

    def registration?
      false
    end

    def authentication?
      false
    end

    class << self
      def for(encoded_client_data_json, origin:, challenge:)
        client_data_json = ClientDataJson.decode encoded_client_data_json

        context = case client_data_json.type
        when 'webauthn.create'
          Registration.new(client_data_json)
        when 'webauthn.get'
          Authentication.new(client_data_json)
        else
          raise 'Unknown Client Data JSON Type'
        end

        context.verify_session!(origin, challenge)
      end
    end
  end
end

require 'web_authn/context/authentication'
require 'web_authn/context/registration'
