# Kisaten
![Kisaten logo](https://github.com/zelivans/kisaten/raw/master/doc/assets/logo_display.png)

[![Gem Version](https://badge.fury.io/rb/kisaten.svg)](https://badge.fury.io/rb/kisaten) [![License](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/zelivans/kisaten/blob/master/LICENSE)


Kisaten is a Ruby extension that enables fuzzing instrumented Ruby code. It implements a fork server and instrumentation that relies on AFL ([american fuzzy lop](http://lcamtuf.coredump.cx/afl/)).

Kisaten works with MRI ([Matz's Ruby Interpreter](https://github.com/ruby/ruby)), other Ruby interpreters are currently not supported. The development of this tool was inspired by [python-afl](https://github.com/jwilk/python-afl) and it works in a similar way that python-afl does with Python.

For bugs found with kisaten see [doc/trophy_case.md](doc/trophy_case.md).

## Installation
### Dependencies
You will most likely need Ruby header files to build the gem. This can be found in most distributions under `ruby-dev` or `ruby-devel`. Build utilities are also needed. For Ubuntu/Debian try `apt-get install ruby-dev build-essential`.

### From RubyGems.org
```
gem install kisaten
```

### From source
Kisaten builds from source with Rake. To build and install the gem, replace * with the correct version number and run:

```
rake gem
gem install ./pkg/kisaten-*.gem 
```

## Usage

1. Include kisaten and initialize with init. The `init` call should come after any initialization code and before the main program logic.

```ruby
require 'kisaten'
# variable initialization, anything that shouldn't be instrumented

Kisaten.init
# code logic
```

2. By default, exceptions are not considered crashes.

Kisaten can catch exceptions and trigger a crash that AFL will catch. The `crash_at` function takes the following parameters: Array of Exception types that will cause a crash, Array of Exception types to ignore, and the crash signal (signal to crash the execution with. Using SIGUSR1 by `Signal.list['USR1']` is a good choice).

For example, to trigger a crash for all exceptions:

```ruby
Kisaten.crash_at [Exception], [], Signal.list['USR1']
```

To crash for all exceptions but not `ArgumentError`:

```ruby
Kisaten.crash_at [Exception], [ArgumentError], Signal.list['USR1']
```

Notice that **all exceptions, even handled ones, are caught by kisaten**. For cases where you must only catch unhandled exceptions, wrap your code in a `begin-end` block and raise an exception that will trigger a crash. You can create a new exception type for this or use something generic like `SystemExit`.

3. The environment variables in ENV_SET configure AFL to work with kisaten. Add them to your script or run:

```
source ENV_SET
```

4. Launch `afl-fuzz` normally. Very likely you will want to configure the `-m` flag so Ruby has enough memory to run.

```
afl-fuzz -i input/ -o output/ -t 1000  -m 1000 -- ruby script.rb @@
```

### Other
* Run Ruby in verbose mode (`-w`) to see kisaten debug messages. When an exception causes kisaten to crash the program, it prints the exception type.
* You can use regular AFL tools such as afl-tmin, afl-cmin, or afl-showmap with kisaten. This is a good way to check if instrumentation is working as expected.

### Persistent mode
AFL persistent mode (afl>=1.82b) can speed up execution considerably. To use with kisaten, call the `loop` function instead of `init`. 

```ruby
while Kisaten.loop 10000
  gc_food = Placeholder.logic(ARGV[0])
end
```

## Development
* If you found a bug, please open an issue on GitHub or send me an email.
* Search for TODO tags in the code to see what is missing or need to be fixed.

### Testing
```
TEST_KISATEN=1 rake compile
rake test
```

## Credits

* [Twistlock](https://www.twistlock.com/) - This open source tool was developed at Twistlock Labs.
