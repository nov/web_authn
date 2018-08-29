module WebAuthn
  class Context
    class Authentication < Context
      def authentication?
        true
      end

      def verify!(authenticator_data, public_key:, sign_count:, signature:)
        # TODO:
      end
    end
  end
end
