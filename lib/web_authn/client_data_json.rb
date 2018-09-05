module WebAuthn
  class ClientDataJSON
    attr_accessor :type, :origin, :challenge, :raw

    def initialize(attrs = {})
      self.type = attrs[:type]
      self.origin = attrs[:origin]
      self.challenge = attrs[:challenge]
      self.raw = attrs[:raw]
    end

    class << self
      def decode(encoded_client_data_json)
        raw_client_data_json = Base64.urlsafe_decode64 encoded_client_data_json
        attrs = JSON.parse(
          raw_client_data_json
        ).merge(
          raw: raw_client_data_json
        ).with_indifferent_access
        attrs[:challenge] = Base64.urlsafe_decode64 attrs[:challenge]
        new attrs
      end
    end
  end
end
