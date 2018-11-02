module WebAuthn
  class AttestationStatement
    class Packed < AttestationStatement
      attr_accessor :alg, :sig

      def initialize(alg:, sig:)
        self.alg = alg
        self.sig = sig
      end

      def verify!(authenticator_data, client_data_json)
        raise 'TODO'
      end

      class << self
        def decode(att_stmt)
          new(
            alg: att_stmt[:alg],
            sig: att_stmt[:sig]
          )
        end
      end
    end
  end
end
