require 'kisaten'
def test_bla
    puts "Bla!"
end

Kisaten.crash_at [RuntimeError], 0

Kisaten.init
