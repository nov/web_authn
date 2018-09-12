module WebAuthn
  class ClientDataJSON
    attr_accessor :type, :origin, :challenge, :raw

    def initialize(type:, origin:, challenge:, raw: nil)
      self.type = type
      self.origin = origin
      self.challenge = challenge
      self.raw = raw
    end

    class << self
      def decode(encoded_client_data_json)
        raw = Base64.urlsafe_decode64 encoded_client_data_json
        json = JSON.parse(raw).with_indifferent_access
        new(
          type: json[:type],
          origin: json[:origin],
          challenge: Base64.urlsafe_decode64(json[:challenge]),
          raw: raw
        )
      end
    end
  end
end
