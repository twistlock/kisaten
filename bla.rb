require 'kisaten'
def test_bla
    puts "Bla!"
end

while Kisaten.loop nil
    test_bla
end

