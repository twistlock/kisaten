# Kisaten
![Kisaten logo](https://github.com/zelivans/kisaten/raw/master/doc/assets/logo_display.png)

Kisaten is a Ruby extension that enables fuzizng instrumented Ruby code. It implements a fork server and instrumentation that relies on AFL ([american fuzzy lop](http://lcamtuf.coredump.cx/afl/)).

Kisaten works with MRI ([Matz's Ruby Interpreter](https://github.com/ruby/ruby)), other Ruby interpeters are currently not supported. The development of this tool was inspired by [afl-python](https://github.com/jwilk/python-afl) and it works in a similiar way that this tool does with Python.

## Installation
### From gem
Todo

### From source
Kisaten builds from source with Rake. To build and install the gem, replace * with the correct version number and run:

```
rake gem
gem install ./pkg/kisaten-*.gem 
```

## Usage


## Development
* If you found a bug, please open an issue on GitHub or send me an email.
* Search for TODO tags in the code to see what is missing or need to be fixed.

### Testing
```
TEST_KISATEN=1 rake compile
rake test
```

## Credits