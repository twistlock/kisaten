require 'kisaten'
require 'json'

Kisaten.crash_at [Exception], [JSON::ParserError], Signal.list['USR1']

while Kisaten.loop 10000
   gc = JSON.parse(File.read(ARGV[0]))
end
