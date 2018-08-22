require 'mkmf'

# have_func returns false if a C function cannot be found.  Sometimes this
# will be OK (the function changed names between versions) and sometimes it is
# not so you need to exit without creating the Makefile.

# abort 'missing malloc()' unless have_func 'malloc'
# abort 'missing free()'   unless have_func 'free'

create_makefile 'kisaten/kisaten'