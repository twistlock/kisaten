#ifndef _KISATEN_INCLUDE
#define _KISATEN_INCLUDE

#include <ruby.h>
#include <ruby/debug.h>
/* TODO: Low: Check if all of these will work with Windows one day */
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/shm.h>

#endif

/* Ruby 2.4 */
#ifndef RB_INTEGER_TYPE_P
#define RB_INTEGER_TYPE_P(obj) (RB_FIXNUM_P(obj) || RB_TYPE_P(obj, T_BIGNUM))
#endif

/* General TODO:
   * Replace all rb_eRuntimeError with a Kisaten error type
   * Consider treating AFL_INST_RATIO one day
*/

/* Constants that must be in sync with afl-fuzz (afl/config.h) */
#define AFL_SHM_ENV_VAR     "__AFL_SHM_ID"
#define AFL_FORKSRV_FD      198
#define AFL_MAP_SIZE_POW2   16
#define AFL_MAP_SIZE        (1 << AFL_MAP_SIZE_POW2)

/* Implementation globals */
unsigned int prev_location = 0;
uint8_t *afl_area_ptr = NULL;

uint8_t use_forkserver = 0;
uint8_t kisaten_init_done = 0;
uint8_t afl_persistent_mode = 0;
int crash_exception_id = 0;

VALUE crash_exception_types = Qnil;
VALUE crash_exception_ignore = Qnil;
VALUE tp_scope_event = Qnil;
VALUE tp_raise_event =  Qnil;

static void kisaten_register_globals()
{
    /* When using global C variables that contain a Ruby value, the code must manually inform the GC of these variable.
       Otherwise they get reaped */
    /* rb_gc_register_address is equivalent to rb_global_variable */
    rb_gc_register_address(&crash_exception_types);
    rb_gc_register_address(&crash_exception_ignore);
    rb_gc_register_address(&tp_scope_event);
    rb_gc_register_address(&tp_raise_event);
}

static void kisaten_unregister_globals()
{
    /* TODO: Figure out if cleanup should be called by the module. Don't want these vars to leak. */
    rb_gc_unregister_address(&crash_exception_types);
    rb_gc_unregister_address(&crash_exception_ignore);
    rb_gc_unregister_address(&tp_scope_event);
    rb_gc_unregister_address(&tp_raise_event);
}

static inline void kisaten_map_shm() 
{
    char *shm_id_str = NULL;
    int shm_id = 0;

    if (NULL != afl_area_ptr)
    {
        rb_raise(rb_eRuntimeError, "Kisaten error: kisaten_map_shm was called but afl_area_ptr is not NULL");
    }

    shm_id_str = getenv(AFL_SHM_ENV_VAR);

    if (!shm_id_str)
    {
        /* rb_warning only prints if $VERBOSE is true. */
        rb_warning("Kisaten failed to get AFL shared memory environment variable");
    }
    else
    {
        errno = 0;
        shm_id = strtol(shm_id_str, NULL, 10); /* Safer atoi */
        if (0 != errno)
        {
            rb_raise(rb_eRuntimeError, "Kisaten failed to read valid integer from AFL_SHM_ENV_VAR!");
        }

        afl_area_ptr = shmat(shm_id, NULL, 0);
        if ((void *) -1 == afl_area_ptr)
        {
            /* TODO: Check errno */
            rb_raise(rb_eRuntimeError, "Kisaten failed to attach AFL shared memory to address space!");
        }
    }
}

/* Inspired by python-afl - using FNV hash algorithm to generate the current_line
   This is a 32-bit Fowler–Noll–Vo hash function based on the jwilk's implementation for python-afl */
static inline uint32_t kisaten_location_fnv_hash(const VALUE path, const VALUE lineno)
{
    long _len; /* In ruby/ruby.h RString->len is type long */
    unsigned char *_path_ptr;
    int _lineno; /* In ruby/vm_trace.c lineno is int */ 

    uint32_t h = 0x811C9DC5; /* Seed(?) for 32-bit */

    /* Type enforcement to prevent segfault */
    if (!RB_INTEGER_TYPE_P(lineno))
    {
        rb_raise(rb_eRuntimeError, "Kisaten internal error: lineno is not an integer.");
    }

    if (T_STRING != TYPE(path))
    {
        rb_raise(rb_eRuntimeError, "Kisaten internal error: path is not a string.");
    }

    _len = RSTRING_LEN(path);
    _path_ptr = RSTRING_PTR(path);
    _lineno = FIX2INT(lineno);

    /* TODO: Someone should verify this C is optimized */
    while (_len > 0)
    {
        h ^= _path_ptr[0];
        h *= 0x01000193;
        _len--;
        _path_ptr++;
    }

    while (_lineno > 0)
    {
        h ^= (unsigned char) _lineno;
        h *= 0x01000193;
        _lineno >>= 8;
    }

    return h;
}

#ifdef TEST_KISATEN_FNV
static VALUE rb_fnv_kisaten(VALUE self, VALUE path, VALUE lineno)
{

    uint32_t result = kisaten_location_fnv_hash(path, lineno);
    return INT2FIX(result);
}
#endif

static void kisaten_scope_event(VALUE self, void *data)
{
    /* Personal: Refer to byebug.c for full debugger example also using debug_context_t */
    rb_trace_arg_t *trace_arg;
    VALUE path, lineno = Qnil;
    unsigned int _cur_location = 0;

    /* TODO: LOW: Check if event is in valid thread */
 
    trace_arg = rb_tracearg_from_tracepoint(self);

    /* Maybe: are rb_tracearg_method_id or rb_tracearg_binding helpful for instrumentation? */
    path = rb_tracearg_path(trace_arg); /* String path */
    lineno = rb_tracearg_lineno(trace_arg); /* Integer line */

    if (NULL != afl_area_ptr)
    {
        /* Refer to afl's technical_details.txt, 1 (Coverage measurements) for info on the injection */
        _cur_location = kisaten_location_fnv_hash(path, lineno) % AFL_MAP_SIZE;
        afl_area_ptr[_cur_location ^ prev_location]++;
        prev_location = _cur_location >> 1;
    }

    /* TODO: Does it not get triggered by this module's C calls? */
}

static void kisaten_raise_event(VALUE self, void *data)
{
    rb_trace_arg_t *trace_arg;
    VALUE raised_exception, _cur_exception_class = Qnil;
    VALUE _exception_class_name = Qnil;
    uint8_t _exception_blacklisted = 0;
    int i = 0;

    trace_arg = rb_tracearg_from_tracepoint(self);
    raised_exception = rb_tracearg_raised_exception(trace_arg);

    if (T_ARRAY != TYPE(crash_exception_types))
    {
        rb_warn("Kisaten :raise event called but crash_exception_types is not an Array");
    }
    else if (T_ARRAY != TYPE(crash_exception_ignore) && !NIL_P(crash_exception_ignore))
    {
        rb_warn("Kisaten :raise event called but crash_exception_ignore is of bad type");
    }
    else
    {
        /* First verify exception class is not blacklisted. 
           This will also verify that it's not a subclass of blacklisted class */
        if (!NIL_P(crash_exception_ignore))
        {
            for (i = 0; i < RARRAY_LENINT(crash_exception_ignore); i++)
            {
                _cur_exception_class = rb_ary_entry(crash_exception_ignore, i);
                if (rb_obj_is_kind_of(raised_exception, _cur_exception_class))
                {
                    _exception_blacklisted = 1;
                    break;
                }
            }
        }

        if (!_exception_blacklisted)
        {
            /* Match raised exception class/subclass with given crash exceptions */
            for (i = 0; i < RARRAY_LENINT(crash_exception_types); i++)
            {
                _cur_exception_class = rb_ary_entry(crash_exception_types, i);
                if (rb_obj_is_kind_of(raised_exception, _cur_exception_class))
                {
                    /* Before crashing, inform the host with warning. This can make it easier to set up fuzzers */
                    /* It should be possible to also get the message with rb_obj_as_string, see exc_inspect code */
                    _exception_class_name = rb_str_dup(rb_class_name(CLASS_OF(raised_exception)));
                    rb_warning("Kisaten crashing execution because exception was raised: %s", StringValuePtr(_exception_class_name)); /* Assume class name can't include null char */

                    /* Crash execution with given signal */
                    if (0 != kill(getpid(), crash_exception_id))
                    {
                        rb_raise(rb_eRuntimeError, "Kisaten catched exception but failed to crash execution with given signal");
                    }
                    break;
                }
            }
        }
    }
}

static void kisaten_trace_begin()
{
    /* TODO: Consider allowing instrumenation by other events other than :line
       Specifically c_call would be interesting and then :call,:call,:b_call, etc. */
    tp_scope_event = rb_tracepoint_new(Qnil, RUBY_EVENT_LINE, kisaten_scope_event, NULL);
    rb_tracepoint_enable(tp_scope_event);

    /* If requested, catch raised exceptions and cause a crash (so afl can catch) */
    /* TODO: The current implementation relies on :raise tracepoint hooks.
       This means it is called on every exception before it is rescued.
       
       Possibly implement something like byebug's post-mortem, then catching only unhandled exceptions.
       Or other ways to detect only unhandled exceptions (i.e. no rescue). */

    if (T_ARRAY == TYPE(crash_exception_types))
    {
        tp_raise_event = rb_tracepoint_new(Qnil, RUBY_EVENT_RAISE, kisaten_raise_event, NULL);
        rb_tracepoint_enable(tp_raise_event);
    }
}

static inline void kisaten_trace_stop()
{
    rb_tracepoint_disable(tp_scope_event);
}

static void kisaten_init()
{
    static uint8_t _tmp[4] = {0};

    ssize_t _cnt = 0;
    int _rc = -1;
    uint32_t _child_killed = 0;
    uint8_t _child_stopped = 0;
    pid_t child_pid = -1;
    int child_status = 0;

    struct sigaction _old_sigchld, _dfl_sigchld;

    /* Reset sigaction structs regardless of their use */
    sigemptyset(&_old_sigchld.sa_mask);
    _old_sigchld.sa_flags = 0;
    _old_sigchld.sa_sigaction = NULL;
    _old_sigchld.sa_handler = SIG_DFL;
    
    sigemptyset(&_dfl_sigchld.sa_mask);
    _dfl_sigchld.sa_flags = 0;
    _dfl_sigchld.sa_sigaction = NULL;
    _dfl_sigchld.sa_handler = SIG_DFL;

    /* Initialization logic begin */

    if (kisaten_init_done)
    {
        rb_raise(rb_eRuntimeError, "Kisaten init already done");
    }

    use_forkserver = 1;

    /* Start the forkserver: "Phone home". 
       If the pipe doesn't exist then assume we are not running in forkserver mode.
       Otherwise failure is considered a bug */
    _cnt = write(AFL_FORKSRV_FD + 1, _tmp, 4);
    if (4 != _cnt)
    {
        if (_cnt < 0 && EBADF == errno)
        {
            /* TODO: Consider a way to allow disabling this warning message.
               It may end up as a bottleneck in some cases where forkserver is not needed */
            rb_warning("Kisaten is running without forkserver");
            use_forkserver = 0;
        }
        else
        {
            rb_raise(rb_eRuntimeError, "Kisaten forkserver initialization failure");
        }
    }

    kisaten_init_done = 1;

    if (use_forkserver)
    {
        /* From my understanding (and sampling) it appears MRI does not set a handler for SIGCHLD here.
           The user code can change the handler though. The code resets it (like in python-afl)

           TODO: Are there any unexpectable implications of temporarily resetting SIGCHLD handler in MRI?
        */
        _rc = sigaction(SIGCHLD, &_dfl_sigchld, &_old_sigchld);
        if (0 != _rc)
        {
            /* TODO: Check errno */
            rb_raise(rb_eRuntimeError, "Kisaten failure setting (DFL) SIGCHLD");
        }  
    }

    while (use_forkserver)
    {
        _cnt = 0;
        _cnt = read(AFL_FORKSRV_FD, &_child_killed, 4);
        if (4 != _cnt)
        {
            rb_raise(rb_eRuntimeError, "Kisaten forkserver failure to read from parent pipe");
        }

        /* This is for when the child has been stopped and afl killed it with SIGKILL */
        if (_child_stopped && _child_killed)
        {
            _child_stopped = 0;
            if (0 > waitpid(child_pid, &child_status, 0))
            {
                rb_raise(rb_eRuntimeError, "Kisaten critical failure on (killed) waitpid");
            }
        }

        if (!_child_stopped)
        {
            /* Child is woke, clone our process */
            child_pid = fork();
            if (0 > child_pid)
            {
                /* TODO: Handle this without runtime error which I'm not sure how will behave */
                rb_raise(rb_eRuntimeError, "Kisaten failure to fork");
            }
            if (!child_pid)
            {        
                /* Continue to instrumentation for the child */
                break;
            }
        }
        else
        {
            /* Persistent mode: if child is alive but stopped give it a SIGCONT to resume */
            if (0 != kill(child_pid, SIGCONT))
            {
                rb_raise(rb_eRuntimeError, "Kisaten persistent mode signal failure");
            }
            _child_stopped = 0;
        }

        /* In parent process write PID to the pipe and wait for the child */
        /* Todo: Low: extremely unlikely scenario of sizeof(t_pid)!=4? */
        _cnt = write(AFL_FORKSRV_FD + 1, &child_pid, 4);
        if (4 != _cnt)
        {
            rb_raise(rb_eRuntimeError, "Kisaten failure writing (child_pid) to parent pipe");
        }

        if (0 > waitpid(child_pid, &child_status, afl_persistent_mode ? WUNTRACED : 0))
        {
            rb_raise(rb_eRuntimeError, "Kisaten critical failure on waitpid");
        }

        /* Persistent mode: the child stops itself with SIGSTOP after running, wake it up without forking again */
        if (WIFSTOPPED(child_status))
        {
            _child_stopped = 1;
        }

        /* Send status back to pipe
           TODO: Low: Make sure sizeof(int) is always good */
        _cnt = write(AFL_FORKSRV_FD + 1, &child_status, 4);
        if (4 != _cnt)
        {
            rb_raise(rb_eRuntimeError, "Kisaten failure writing (status) to parent pipe");
        }

    }

    /* Instrumentation logic continue (in child if forkserver) */
    if (use_forkserver)
    {
        /* Return the original SIGCHLD */
        _rc = sigaction(SIGCHLD, &_old_sigchld, NULL);
        if (0 != _rc)
        {
            /* TODO: Check errno */
            rb_raise(rb_eRuntimeError, "Kisaten failure returning SIGCHLD");
        }

        /* Clean descriptors for child */
        if (0 > close(AFL_FORKSRV_FD) || 0 > close(AFL_FORKSRV_FD + 1))
        {
            /* I am not sure of the implications of failing here so only warn */
            rb_warn("Kisaten warning: failed to clean FORKSRV_FDs in child");
        }
    }

    /* Get AFL shared memory before starting instrumentation */
    kisaten_map_shm();

    kisaten_trace_begin();
}

static VALUE rb_init_kisaten(VALUE self)
{
    afl_persistent_mode = 0;
    kisaten_init();
    return Qnil;
}

static VALUE rb_loop_kisaten(VALUE self, VALUE max_count)
{
    static int _saved_max_cnt = 0;
    static uint8_t _first_pass = 1;
    static uint32_t _run_cnt = 0;

    /* Note: LLVM mode and python-afl use an enviroment variable to enforce persistent mode.
       Currently not implementating unless it has a good reason */

    if (_first_pass)
    {
        /* Check if given max_count is valid */
        if (!RB_INTEGER_TYPE_P(max_count) && !NIL_P(max_count))
        {
            rb_raise(rb_eRuntimeError, "Kisaten loop max_count must be an integer or nil (for infinite)");
        }

        if (NIL_P(max_count))
        {
            /* nil max_count means infinite loop */
            _saved_max_cnt = -1;
        }
        else
        {
            _saved_max_cnt = NUM2INT(max_count);
            if (0 >= _saved_max_cnt)
            {
                /* Return without doing anything, next run will be like new */
                return Qfalse;
            }
        }

        /* Start the fork server with persistent mode */
        afl_persistent_mode = 1;
        prev_location = 0;

        kisaten_init();

        _first_pass = 0;
        _run_cnt++;

        return Qtrue;
    }

    if (_run_cnt < _saved_max_cnt)
    {
        if (0 != kill(getpid(), SIGSTOP))
        {
            /* TODO: Low: should this be an error? Maybe just return Qfalse and log? */
            rb_raise(rb_eRuntimeError, "Kisaten failed to raise SIGSTOP");
        }

        _run_cnt++;
        return Qtrue;
    }
    else
    {
        /* Loop has ended, disable instrumentation for the rest of the Ruby code */
        kisaten_trace_stop();
        return Qfalse;
    }
}

/* This function will be used to set exceptions that should crash execution */
static VALUE rb_crash_at_kisaten(VALUE self, VALUE arr_exceptions, VALUE arr_ignore, VALUE int_crash_id)
{
    if (kisaten_init_done)
    {
        /* TODO: Consider allowing calling crash_at after init if there is a need for it.
           Basically just need to set or remove the raise TP if changed */
        rb_raise(rb_eRuntimeError, "Kisaten init already done, crash_at currently unsupported");
    }

    /* Allow "reset" by setting nil,nil,nil */
    if (NIL_P(arr_ignore) && NIL_P(arr_exceptions) && NIL_P(int_crash_id))
    {
        crash_exception_types = Qnil;
        crash_exception_ignore = Qnil;
        crash_exception_id = 0;
        return Qtrue;
    }

    /* Check types
       Accept only arrays for exception and ignore list
       Accept only integer for crash id. Can be found with Signal, i.e Signal.list["USR1"] */
    if (T_ARRAY != TYPE(arr_exceptions))
    {
        rb_raise(rb_eRuntimeError, "Kisaten.crash_at needs an Array for crash exceptions list");
    }
    if (T_ARRAY != TYPE(arr_ignore) && !NIL_P(arr_ignore))
    {
        rb_raise(rb_eRuntimeError, "Kisaten.crash_at needs an Array for ignore exceptions list");
    }
    if (!RB_INTEGER_TYPE_P(int_crash_id))
    {
        rb_raise(rb_eRuntimeError, "Kisaten.crash_at crash exception signal ID must be an integer");   
    }
    
    crash_exception_types = rb_ary_dup(arr_exceptions);
    /* Secretly allow nil for ignore list */
    if (NIL_P(arr_ignore))
    {
        crash_exception_ignore = Qnil;
    }
    else
    {
        crash_exception_ignore = rb_ary_dup(arr_ignore);
    }
    crash_exception_id = NUM2INT(int_crash_id);

    return Qtrue;
}

void Init_kisaten()
{
    VALUE rb_mKisaten = Qnil;

    rb_mKisaten = rb_define_module("Kisaten");
    rb_define_singleton_method(rb_mKisaten, "init", rb_init_kisaten, 0);
    rb_define_singleton_method(rb_mKisaten, "loop", rb_loop_kisaten, 1);
    rb_define_singleton_method(rb_mKisaten, "crash_at", rb_crash_at_kisaten, 3);
#ifdef TEST_KISATEN_FNV
    rb_define_singleton_method(rb_mKisaten, "_fnv", rb_fnv_kisaten, 2);
#endif

    kisaten_register_globals();
}