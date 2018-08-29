require 'simplecov'

SimpleCov.start do
  add_filter 'spec'
end

require 'rspec'
require 'rspec/its'
require 'web_authn'

RSpec.configure do |config|
  config.expect_with :rspec do |c|
    c.syntax = [:should, :expect]
  end
end
