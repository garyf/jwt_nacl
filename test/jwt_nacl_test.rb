require "test_helper"

class JwtNaclTest < Minitest::Test
  def test_that_it_has_a_version_number
    refute_nil ::JwtNacl::VERSION
  end
end
