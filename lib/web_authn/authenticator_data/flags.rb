module WebAuthn
  class AuthenticatorData
    class Flags
      _flags_ = [:up, :uv, :be, :bs, :at, :ex]
      attr_accessor *_flags_
      _flags_.each do |flag|
        alias_method :"#{flag}?", flag
      end

      def initialize(up:, uv:, be:, bs:, at:, ex:)
        self.up = up
        self.uv = uv
        self.be = be
        self.bs = bs
        self.at = at
        self.ex = ex
      end

      def ==(target)
        up == target.up &&
        uv == target.uv &&
        be == target.be &&
        bs == target.bs &&
        at == target.at &&
        ex == target.ex
      end

      class << self
        def decode(input)
          bit_array = input.getbyte(0)
          new(
            up: bit_array[0] == 1,
            uv: bit_array[2] == 1,
            be: bit_array[4] == 1,
            bs: bit_array[5] == 1,
            at: bit_array[6] == 1,
            ex: bit_array[7] == 1,
          )
        end
      end
    end
  end
end
