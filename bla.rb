require 'kisaten'
def test_bla
    puts "Bla!"
end

Kisaten.crash_at [RuntimeError], Signal.list["USR1"]

Kisaten.init
