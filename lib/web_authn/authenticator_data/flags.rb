module WebAuthn
  class AuthenticatorData
    class Flags
      _flags_ = [:up, :uv, :at, :ex]
      attr_accessor *_flags_
      _flags_.each do |flag|
        alias_method :"#{flag}?", flag
      end

      def initialize(up:, uv:, at:, ex:)
        self.up = up
        self.uv = uv
        self.at = at
        self.ex = ex
      end

      class << self
        def decode(input)
          bit_array = input.getbyte(0)
          new(
            up: bit_array[0] == 1,
            uv: bit_array[2] == 1,
            at: bit_array[6] == 1,
            ex: bit_array[7] == 1
          )
        end
      end
    end
  end
end
