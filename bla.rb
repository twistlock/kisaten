require 'kisaten'
def test_bla
    puts "Bla!"
end

Kisaten.crash_at nil, nil

while Kisaten.loop nil
    test_bla
end

