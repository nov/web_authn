module WebAuthn
  class ClientDataJSON
    attr_accessor :type, :origin, :challenge

    def initialize(attrs = {})
      self.type = attrs[:type]
      self.origin = attrs[:origin]
      self.challenge = attrs[:challenge]
    end

    class << self
      def decode(encoded_client_data_json)
        new JSON.parse(
          Base64.urlsafe_decode64 encoded_client_data_json
        ).with_indifferent_access
      end
    end
  end
end
