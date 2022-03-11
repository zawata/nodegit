#include <node.h>
#include <v8.h>

#include <dlfcn.h>
#include <git2.h>
#include <map>
#include <algorithm>
#include <set>
#include <mutex>
#include <iostream>

#include "../include/init_ssh2.h"
#include "../include/lock_master.h"
#include "../include/nodegit.h"
#include "../include/context.h"
#include "../include/wrapper.h"
#include "../include/promise_completion.h"
#include "../include/functions/copy.h"
{% each %}
  {% if type != "enum" %}
    #include "../include/{{ filename }}.h"
  {% endif %}
{% endeach %}
#include "../include/convenient_patch.h"
#include "../include/convenient_hunk.h"
#include "../include/filter_registry.h"

using namespace v8;

void cleanup(void *);

Local<Value> GetPrivate(Local<Object> object, Local<String> key) {
  Local<Value> value;
  Nan::Maybe<bool> result = Nan::HasPrivate(object, key);
  if (!(result.IsJust() && result.FromJust()))
    return Local<Value>();
  if (Nan::GetPrivate(object, key).ToLocal(&value))
    return value;
  return Local<Value>();
}

void SetPrivate(Local<Object> object, Local<String> key, Local<Value> value) {
  if (value.IsEmpty())
    return;
  Nan::SetPrivate(object, key, value);
}

//OpenSSL symbol forward declarations
#define CRYPTO_LOCK 1
typedef void CRYPTO_THREADID;

//These are static because otherwise they will interfere with the imported symbols in libgit2/src/streams/openssl_dynamic.c
static unsigned int (*OpenSSL_version_num)(void);
static void (*CRYPTO_THREADID_set_numeric)(CRYPTO_THREADID *id, unsigned long val);
static int (*CRYPTO_THREADID_set_callback)(void (*threadid_func)(CRYPTO_THREADID *));
static int (*CRYPTO_num_locks)(void);
static void (*CRYPTO_set_locking_callback)(void (*locking_function)(int mode, int n, const char *file, int line));

static void *openssl_handle = nullptr;

static uv_mutex_t *opensslMutexes;

void OpenSSL_LockingCallback(int mode, int type, const char *, int) {
  if (mode & CRYPTO_LOCK) {
    uv_mutex_lock(&opensslMutexes[type]);
  } else {
    uv_mutex_unlock(&opensslMutexes[type]);
  }
}

void OpenSSL_IDCallback(CRYPTO_THREADID *id) {
  CRYPTO_THREADID_set_numeric(id, (unsigned long)uv_thread_self());
}

void OpenSSL_ThreadSetup() {
  //if these aren't loaded, then we're in a high-enough openssl version that doesn't require thread setup
  // therefore, we can just bail without doing anything
  if(!CRYPTO_THREADID_set_numeric ||
     !CRYPTO_THREADID_set_callback ||
     !CRYPTO_num_locks ||
     !CRYPTO_set_locking_callback) {
    return;
  }
  opensslMutexes=(uv_mutex_t *)malloc(CRYPTO_num_locks() * sizeof(uv_mutex_t));

  for (int i=0; i<CRYPTO_num_locks(); i++) {
    uv_mutex_init(&opensslMutexes[i]);
  }

  CRYPTO_set_locking_callback(OpenSSL_LockingCallback);
  CRYPTO_THREADID_set_callback(OpenSSL_IDCallback);
}

// diagnostic function
NAN_METHOD(GetNumberOfTrackedObjects) {
  nodegit::Context *currentNodeGitContext = nodegit::Context::GetCurrentContext();
  assert (currentNodeGitContext != nullptr);
  info.GetReturnValue().Set(currentNodeGitContext->TrackerListSize());
}

static std::once_flag libraryInitializedFlag;
static std::mutex libraryInitializationMutex;

#define load_symbol(sym, required) _load_symbol((void **)&sym, #sym, required)
void _load_symbol(void **ptr, const char *func, bool required) {
  *ptr = dlsym(openssl_handle, func);
  if(!*ptr && required) {
    std::cout << "error with " << func << ": " << dlerror() << std::endl;
  }
}

NAN_MODULE_INIT(init) {
  {
    // With libgit2's dynamic openssl loading, we no longer need to compile against it but we do
    // still need access to some symbols here.
    // Additionally, because of the flags libgit2 passes to dlopen, node attempts to override various symbols
    // in libssl on load which could cause ABI issues for us later.
    // Theres 2 fixes for this problem
    //   1. recompile node such that it doesn't export libssl and libcrypto symbols and ship that with nodegit
    //   2. force an early dlopen call with RTLD_DEEPBIND set to make libssl prefer it's own symbols over node's
    // you tell me which one is easier

    if(!openssl_handle) {
      //replicate libgit2's dlopen logic with new flags
      if ((openssl_handle = dlopen("libssl.so.1.1", RTLD_NOW | RTLD_DEEPBIND)) == NULL &&
          (openssl_handle = dlopen("libssl.1.1.dylib", RTLD_NOW | RTLD_DEEPBIND)) == NULL &&
          (openssl_handle = dlopen("libssl.so.1.0.0", RTLD_NOW | RTLD_DEEPBIND)) == NULL &&
          (openssl_handle = dlopen("libssl.1.0.0.dylib", RTLD_NOW | RTLD_DEEPBIND)) == NULL &&
          (openssl_handle = dlopen("libssl.so.10", RTLD_NOW | RTLD_DEEPBIND)) == NULL) {
        std::cerr << "Could not load openssl. I don't know what to do now. I guess I'll just crash?" << std::endl;
        openssl_handle = nullptr;
      }

      load_symbol(OpenSSL_version_num, true);

      // starting with openssl version 1.1, openssl is mostly threadsafe and locking callbacks are no longer used
      // https://stackoverflow.com/questions/60587434/how-crypto-num-locks-will-return-required-number-of-locks
      bool required = OpenSSL_version_num() < 0x10100000UL;
      load_symbol(CRYPTO_THREADID_set_numeric, required);
      load_symbol(CRYPTO_THREADID_set_callback, required);
      load_symbol(CRYPTO_num_locks, required);
      load_symbol(CRYPTO_set_locking_callback, required);
    }
  }
  {
    // We only want to do initialization logic once, and we also want to prevent any thread from completely loading
    // the module until initialization has occurred.
    // All of this initialization logic ends up being shared.
    const std::lock_guard<std::mutex> lock(libraryInitializationMutex);
    std::call_once(libraryInitializedFlag, []() {
      // Initialize thread safety in openssl and libssh2
      OpenSSL_ThreadSetup();
      init_ssh2();
      // Initialize libgit2.
      git_libgit2_init();

      // Register thread pool with libgit2
      nodegit::ThreadPool::InitializeGlobal();
    });
  }

  // Exports function 'getNumberOfTrackedObjects'
  Nan::Set(target
    , Nan::New<v8::String>("getNumberOfTrackedObjects").ToLocalChecked()
    , Nan::GetFunction(Nan::New<v8::FunctionTemplate>(GetNumberOfTrackedObjects)).ToLocalChecked()
  );

  Nan::HandleScope scope;
  Local<Context> context = Nan::GetCurrentContext();
  Isolate *isolate = context->GetIsolate();
  nodegit::Context *nodegitContext = new nodegit::Context(isolate);

  //register envioronment destructor
  AddEnvironmentCleanupHook(isolate, cleanup, nullptr);

  Wrapper::InitializeComponent(target, nodegitContext);
  PromiseCompletion::InitializeComponent(nodegitContext);
  {% each %}
    {% if type == 'class' %}
      {{ cppClassName }}::InitializeComponent(target, nodegitContext);
    {% elsif type == 'struct' %}
    {% if isReturnable %}
      {{ cppClassName }}::InitializeComponent(target, nodegitContext);
    {% endif %}
    {% endif %}
  {% endeach %}

  ConvenientHunk::InitializeComponent(target, nodegitContext);
  ConvenientPatch::InitializeComponent(target, nodegitContext);
  GitFilterRegistry::InitializeComponent(target, nodegitContext);

  nodegit::LockMaster::InitializeContext();
}

void cleanup(void *) {
  // dlopen uses a ref-counting system so we need to close it here and in libgit2
  if(openssl_handle) {
    dlclose(openssl_handle);
    openssl_handle = nullptr;
  }
}

NAN_MODULE_WORKER_ENABLED(nodegit, init)
