RSpec.describe WebAuthn::AuthenticatorData::Flags do
  describe '.decode' do
    subject { described_class.decode [bits].pack('b*') }

    describe 'when all false' do
      let(:bits) { '00000000' }
      its(:up?) { should == false }
      its(:uv?) { should == false }
      its(:at?) { should == false }
      its(:ex?) { should == false }
    end

    describe 'when up is on' do
      let(:bits) { '10000000' }
      its(:up?) { should == true }
      its(:uv?) { should == false }
      its(:at?) { should == false }
      its(:ex?) { should == false }
    end

    describe 'when uv is on' do
      let(:bits) { '00100000' }
      its(:up?) { should == false }
      its(:uv?) { should == true }
      its(:at?) { should == false }
      its(:ex?) { should == false }
    end

    describe 'when at is on' do
      let(:bits) { '00000010' }
      its(:up?) { should == false }
      its(:uv?) { should == false }
      its(:at?) { should == true }
      its(:ex?) { should == false }
    end

    describe 'when ex is on' do
      let(:bits) { '00000001' }
      its(:up?) { should == false }
      its(:uv?) { should == false }
      its(:at?) { should == false }
      its(:ex?) { should == true }
    end
  end
end
