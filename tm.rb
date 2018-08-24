require 'kisaten'

def bla
    puts 'Blabla'
end

Kisaten.crash_at [Exception], Signal.list['USR1']

while Kisaten.loop 1000
    bla
end
