require 'minitest/autorun'
require 'kisaten'

class KisatenTest < Minitest::Test

  def test_crash_at
    assert_equal Kisaten.crash_at(nil, nil, nil), true
    assert_equal Kisaten.crash_at([], [], 0), true
    assert_equal Kisaten.crash_at([Exception], [Errno::EINVAL], Signal.list['USR1']), true
    assert_raises(RuntimeError) { Kisaten.crash_at("Fake", [], 0) }
    assert_raises(RuntimeError) { Kisaten.crash_at([], "Fake", 0) }
    assert_raises(RuntimeError) { Kisaten.crash_at([], [], "Fake") }
  end

  def test_fnv_hash
    skip "Compile kisaten with TEST_KISATEN=1 to test FNV function" if !Kisaten.respond_to? :_fnv
    # Same tests as in python-afl
    assert_equal 2166136261, Kisaten._fnv('', 0)
    assert_equal 789356349, Kisaten._fnv('', 42)
    assert_equal 3934561083, Kisaten._fnv('moo', 23)
    assert_equal 3162790609, Kisaten._fnv('moo', 37)
    assert_equal 2298935884, Kisaten._fnv('wół', 23)
    assert_equal 3137816834, Kisaten._fnv('wół', 37)
  end

  # TODO: Write tests checking forkserver and instrumentation working by launching a different Ruby instance
  # Or any other hacky way by modifying the C code
end