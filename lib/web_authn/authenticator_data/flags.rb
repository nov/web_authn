module WebAuthn
  class AuthenticatorData
    class Flags
      attr_accessor :up, :uv, :at, :ex

      def initialize(_flags_)
        self.up =_flags_[0]
        self.uv =_flags_[2]
        self.at =_flags_[6]
        self.ex =_flags_[7]
      end

      def up?; up == 1; end
      def uv?; uv == 1; end
      def at?; at == 1; end
      def ex?; ex == 1; end
    end
  end
end
