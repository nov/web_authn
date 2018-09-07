module WebAuthn
  class AuthenticatorData
    attr_accessor :rp_id_hash, :flags, :sign_count, :attested_credential_data, :raw

    %i(credential_id public_key).each do |method|
      delegate method, to: :attested_credential_data, allow_nil: true
    end

    def initialize(rp_id_hash:, flags:, sign_count:, raw:, attested_credential_data: nil)
      self.rp_id_hash = rp_id_hash
      self.flags = flags
      self.sign_count = sign_count
      self.raw = raw
      self.attested_credential_data = attested_credential_data
    end

    class << self
      def decode(auth_data)
        rp_id_hash,
        _flags_,
        sign_count = [
          auth_data.byteslice(0...32),
          auth_data.byteslice(32),
          auth_data.byteslice(33...37)
        ]
        flags = Flags.decode(_flags_)
        attested_credential_data = if flags.at?
          if flags.ex?
            raise NotImplementedError, 'Extension Data Not Supported Yet'
          else
            AttestedCredentialData.decode auth_data.byteslice(37..-1)
          end
        else
          nil
        end

        new(
          rp_id_hash: Base64.urlsafe_encode64(rp_id_hash, padding: false),
          flags: flags,
          sign_count: sign_count.unpack('N1').first,
          attested_credential_data: attested_credential_data,
          raw: auth_data
        )
      end
    end
  end
end

require 'web_authn/authenticator_data/flags'
