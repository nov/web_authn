require 'simplecov'

SimpleCov.start do
  skip 'spec'
end

require 'rspec'
require 'rspec/its'
require 'web_authn'

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = [:should, :expect]
  end
end

require 'support/context_factory'
