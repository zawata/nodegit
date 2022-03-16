#include <node.h>
#include <v8.h>

#include <git2.h>
#include <map>
#include <algorithm>
#include <set>
#include <mutex>
#include <iostream>

#include "../include/init_ssh2.h"
#include "../include/init_openssl.h"
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

// diagnostic function
NAN_METHOD(GetNumberOfTrackedObjects) {
  nodegit::Context *currentNodeGitContext = nodegit::Context::GetCurrentContext();
  assert (currentNodeGitContext != nullptr);
  info.GetReturnValue().Set(currentNodeGitContext->TrackerListSize());
}

static std::once_flag libraryInitializedFlag;
static std::mutex libraryInitializationMutex;


NAN_MODULE_INIT(init) {
  //init openssl if necessary before we do anything
  init_openssl();
  {
    // We only want to do initialization logic once, and we also want to prevent any thread from completely loading
    // the module until initialization has occurred.
    // All of this initialization logic ends up being shared.
    const std::lock_guard<std::mutex> lock(libraryInitializationMutex);
    std::call_once(libraryInitializedFlag, []() {
      // Initialize thread safety in openssl and libssh2
      init_openssl_threading();
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
  deinit_openssl();
}

NAN_MODULE_WORKER_ENABLED(nodegit, init)
