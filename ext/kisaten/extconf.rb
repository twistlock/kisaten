require 'mkmf'

# This environment variable should be used when compiling the extension for testing
if ENV["TEST_KISATEN"]
  $defs.push("-DTEST_KISATEN_FNV") unless $defs.include? "-TEST_KISATEN_FNV"
end

create_makefile 'kisaten/kisaten'
