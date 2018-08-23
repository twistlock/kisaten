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
   * Write tests white/blackbox
   * Defered mode
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

VALUE tp_scope_event = Qnil;

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
        /* rb_warning only prints if $VERBOSE is true. 
           This could allow info here while not interfering with the program too much.
           TODO: Allow passing when needed with a flag in init/env var
         */
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

    _len = RSTRING_LEN(path);
    _path_ptr = RSTRING_PTR(path);
    _lineno = FIX2INT(lineno);

    /* TODO: Someone should verify this C is optimized */
    /* TODO: Debug + Write test for this! Test without + with real ruby tracepoint data */
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

static void kisaten_scope_event(VALUE self, void *data)
{
    /* Personal: Refer to byebug.c for full debugger example also using debug_context_t */
    rb_trace_arg_t *trace_arg;
    VALUE path, lineno;
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
    /* rb_tracepoint_disable(self); */
}

static void kisaten_trace_begin()
{
    /* TODO: Find all possible events in ruby.h
       TODO: PRIOROTY: Check if also need other events for scope, such as :thread_begin 
       TODO: PRIORITY: Raise events, C function calls
    */
    tp_scope_event = rb_tracepoint_new(Qnil, RUBY_EVENT_B_CALL |
                                                   RUBY_EVENT_CALL |
                                                   RUBY_EVENT_CLASS,
                                                   kisaten_scope_event, NULL);
    rb_tracepoint_enable(tp_scope_event);
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
            rb_raise(rb_eRuntimeError, "Kisaten failure resetting SIGCHLD");
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
            {        _rc = sigaction(SIGCHLD, &_dfl_sigchld, &_old_sigchld);
        if (0 != _rc)
        {
            /* TODO: Check errno */
            rb_raise(rb_eRuntimeError, "Kisaten failure resetting SIGCHLD");
        }
                /* Continue to instrumentation for the child */
                break;
            }
        }
        else
        {
            /* Persistent mode: if child is alive but stopped give it a SIGCONT to resume */
            if (0 > kill(child_pid, SIGCONT))
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

    /* TODO: PRIORITY: Exception hook
       accept exception ID in init and set it in MRI */

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

void Init_kisaten()
{
    VALUE rb_mKisaten = Qnil;

    rb_mKisaten = rb_define_module("Kisaten");
    rb_define_singleton_method(rb_mKisaten, "init", rb_init_kisaten, 0);
    rb_define_singleton_method(rb_mKisaten, "loop", rb_loop_kisaten, 1);
}