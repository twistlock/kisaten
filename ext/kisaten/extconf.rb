require 'mkmf'

# This environment variable should be used when compiling the extension for testing
# Will set if the env is not defined (or set to 0)
if "0" != ENV.fetch("TEST_KISATEN") { "0" }
  $defs.push("-DTEST_KISATEN_FNV") unless $defs.include? "-TEST_KISATEN_FNV"
end

create_makefile 'kisaten/kisaten'
