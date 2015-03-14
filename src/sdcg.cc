// Copyright 2014 Chengyu Song. All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
//       notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
//       copyright notice, this list of conditions and the following
//       disclaimer in the documentation and/or other materials provided
//       with the distribution.
//     * Neither the name of Google Inc. nor the names of its
//       contributors may be used to endorse or promote products derived
//       from this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#include "v8.h"

#ifdef SEC_DYN_CODE_GEN
#include <unistd.h>
#include <sched.h>
#include <dirent.h>
#include <errno.h>
#include <linux/unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/signal.h>
#include <sys/socket.h>

#include "platform.h"
#include "platform-posix.h"
#include "codegen.h"
#include "full-codegen.h"
#include "scopes.h"
#include "x64/lithium-codegen-x64.h"
#include "sdcg.h"

int sdcg_mode = 0;

#if V8_TARGET_ARCH_X64
#define NR_MMAP __NR_mmap
#else
#define NR_MMAP __NR_mmap2
#endif

//#define SDCG_PROT_WRITE 0
#define SDCG_PROT_WRITE PROT_WRITE

namespace v8 {
namespace internal {

#define SDCG_SHARED_VM_SIZE 0x80000000

uint8_t* sdcg_shared_vm_start = NULL;
uint8_t* sdcg_shared_vm_current = NULL;
uint8_t* sdcg_shared_vm_end = NULL;
uint8_t* sdcg_scratch_page = NULL;
volatile uint8_t* sdcg_stack_base = NULL;

// FIXME: this is from seccomp-sandbox, should merge with the seccomp-bpf-sandbox
//
struct sdcg_secure_mem {
  union {
    struct {
      union {
        struct {
          struct sdcg_secure_mem *self;
          unsigned long seq;
          unsigned long call_type;
          unsigned long func_num;
          void* arg1;
          void* arg2;
          void* arg3;
          void* arg4;
          void* arg5;
          void* arg6;
          void* ret;

          struct sdcg_secure_mem *new_secure_mem;

          unsigned long index;
          pid_t tid;
          int fd_pub;
          int fd;

          uint64_t ustart;
        } __attribute__((packed)) _ci;
        unsigned char header[512];
      };
      char pathname[4096 - 512];
    } __attribute__((packed)) _cc;
    unsigned char secure_page[4096];
  };
  union {
    struct {
    } __attribute__((packed)) _rpc_info;
    unsigned char scratch_page[4096];
  };
  union {
    struct {
      uint8_t *stack_top;
      size_t stack_size;
    } __attribute__((packed)) _stack_info;
    unsigned char stack[16*KB];
  };
} __attribute__((packed));
static struct sdcg_secure_mem* secure_mem = NULL;

static int process_fd;
static int process_fd_pub;
static int thread_fd;
static int thread_fd_pub;
static Mutex* sdcg_mutex; //FIXME should be multi-threaded

// FIXME: some of these have been abandoned
enum sdcg_request {
  SDCG_MMAP, //0
  SDCG_RESERVE, //1
  SDCG_COLLECT_ALL_GARBAGE, //2
  SDCG_PREPARE_FOR_MARK_COMPACT, //3
  SDCG_MARK_COMPACT_VISIT, //4
  SDCG_SWEEP_CODE_SPACE, //5
  SDCG_MAKE_CODE, //6
  SDCG_ACTIVE_CODE, //7
  SDCG_COPY_CODE, //8
  SDCG_NEW_CODE, //9
  SDCG_FINISH_CODE, //10
  SDCG_IC_MISS, //11
  SDCG_SET_TARGET_AT, //12
  SDCG_SET_TARGET_OBJECT, //13
  SDCG_WRITE_FIELD, //14
  SDCG_COPY_BYTES, //15
  SDCG_PATCH_INLINE_SMI_CODE, //16
  SDCG_PATCH_INTERRUPT_CODE, //17
  SDCG_REVERT_INTERRUPT_CODE, //18
  SDCG_MAKE_CODE_EPILOGUE, //19
  SDCG_PATCH_INCREMENTAL_MARKING, //20
  SDCG_PROCESS_MARKING_QUEUE, //21
  SDCG_PATCH_CODE_AGE, //22
  SDCG_PATCH_RECORD_WRITE_STUB, //23
  SDCG_EVACUATE_LIVE_OBJECTS, //24
  SDCG_REGEXP_COMPILE, //25
  SDCG_EMPTY_MARKING_DEQUE, 
  MAX_FUNCN
};

struct request_header {
  int funcn;
  unsigned long index;
  uint64_t start;
} __attribute__((packed));

struct return_header {
  uint64_t start;
  void* result;
} __attribute__((packed));

#define SDCG_GET_REQUEST() \
  do { \
    if (syscall(__NR_read, process_fd_pub, &request, sizeof(request)) != sizeof(request)) { \
      V8_Fatal(__FILE__, __LINE__, "failed to read request"); \
    } \
  } while (0)

static void sdcg_dispatch_cmd(struct request_header *header);

static inline void sdcg_send_request(void* q, size_t qs, void* r, size_t rs, 
                                    bool copy_stack = false, bool lock = true) {
  uint8_t* rsp = (uint8_t*)q;
  size_t ss = 0;
  struct return_header rh;

  //if (lock) sdcg_mutex->Lock();

#if 0
  struct request_header *header = (struct request_header*)q;
  header->start = OS::Ticks();
#endif

  if (copy_stack) {
    if (sdcg_stack_base <= rsp) {
      V8_Fatal(__FILE__, __LINE__, "invalid stack base\n");
    }

    ss = sdcg_stack_base - rsp;
    ASSERT(ss < 8*KB);

    //fprintf(stderr, "base %p, current %p\n", sdcg_stack_base, rsp);
    secure_mem->_stack_info.stack_top = rsp;
    secure_mem->_stack_info.stack_size  = ss;
    memcpy(secure_mem->stack + sizeof(rsp) + sizeof(ss), rsp, ss);
  } else {
    secure_mem->_stack_info.stack_size = 0;
  }

  //fprintf(stderr, "base = %p, rsp = %p, size %ld\n", sdcg_stack_base, rsp, ss);

  if (write(process_fd, q, qs) != (ssize_t)qs) {
    V8_Fatal(__FILE__, __LINE__, "failed to send request");
  }

  //if (read(process_fd, r, rs) != (ssize_t)rs) {
  if (read(process_fd, &rh, sizeof(rh)) != sizeof(rh)) {
    V8_Fatal(__FILE__, __LINE__, "failed to read result");
  }
  memcpy(r, &rh.result, rs);

  //if (lock) sdcg_mutex->Unlock();
}

static inline void sdcg_return(void* r, size_t rs) {
  struct return_header rh;
  //uint8_t* rsp = secure_mem->_stack_info.stack_top;
  //size_t ss = secure_mem->_stack_info.stack_size;

#if 0
  //secure_mem->_cc._ci.ustart = OS::Ticks();
  rh.start = OS::Ticks();
#endif

  memcpy(&rh.result, r, rs);
  syscall(__NR_write, process_fd_pub, &rh, sizeof(rh));
}

void sdcg_shared_vm_init() {
  if (sdcg_shared_vm_start != NULL)
    return;

  sdcg_shared_vm_start = (uint8_t*)syscall(NR_MMAP,
                                          OS::GetRandomMmapAddr(),
                                          SDCG_SHARED_VM_SIZE,
                                          PROT_NONE,
                                          MAP_SHARED | MAP_ANONYMOUS | MAP_NORESERVE,
                                          -1,
                                          0);

  if (sdcg_shared_vm_start == MAP_FAILED) {
    V8_Fatal(__FILE__, __LINE__, "SIM failed allocate shared memory");
    return;
  }

  sdcg_scratch_page = (uint8_t*)syscall(NR_MMAP,
                                       (void*)(0x80000000),
                                       4096,
                                       PROT_READ|PROT_WRITE,
                                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE | MAP_FIXED,
                                       -1,
                                       0);

  if (sdcg_scratch_page == MAP_FAILED) {
    V8_Fatal(__FILE__, __LINE__, "SIM failed allocate scratch memory");
    return;
  }

  sdcg_shared_vm_end = sdcg_shared_vm_start + SDCG_SHARED_VM_SIZE;
  sdcg_shared_vm_current = sdcg_shared_vm_start;

  sdcg_mutex = OS::CreateMutex();
}

void* sdcg_reserve(size_t size) {
  void* result = MAP_FAILED;
  int magic = __NR_munmap;
  struct {
    struct request_header header;
    uint8_t* current;
  } __attribute__((packed)) request;
  const size_t msize = RoundUp(size, 4096);

  if (sdcg_shared_vm_start == NULL)
    sdcg_shared_vm_init();

  if (sdcg_shared_vm_current + msize >= sdcg_shared_vm_end) {
    V8_Fatal(__FILE__, __LINE__, 
             "SIM reserve memory overflow: base %p, current %p, size %x",
             sdcg_shared_vm_start, sdcg_shared_vm_current, size);
    return result;
  }

  result = sdcg_shared_vm_current;
  sdcg_shared_vm_current += msize;

  if (sdcg_mode == 2) {
    secure_mem->_cc._ci.func_num = __NR_munmap;
    secure_mem->_cc._ci.arg1 = sdcg_shared_vm_current;

    syscall(__NR_write, thread_fd_pub, &magic, sizeof(magic));
    syscall(__NR_read, thread_fd_pub, &magic, sizeof(magic));
  } else if (sdcg_mode == 1) {
    request.header.funcn = SDCG_RESERVE;
    request.current = sdcg_shared_vm_current;

    sdcg_send_request(&request, sizeof(request), &magic, sizeof(magic), false);
  }

  return result;
}

static inline void handle_reserve() {
  struct {
    uint8_t* current;
  } __attribute__((packed)) request;
  int magic = SDCG_RESERVE;

  SDCG_GET_REQUEST();

  if (request.current < sdcg_shared_vm_current) {
    V8_Fatal(__FILE__, __LINE__, "new current is less than old");
  }

  sdcg_shared_vm_current = request.current;

  sdcg_return(&magic, sizeof(magic));
}

extern void UpdateAllocatedSpaceLimits(void* address, int size);

struct mmap_request {
  void* base;
  size_t size;
  int prot;
} __attribute__((packed));

void* sdcg_mmap(void* base, size_t size, int prot) {
  int prot_sim = prot;
  int magic = __NR_mmap;
  void* rbase;
  struct {
    struct request_header header;
    struct mmap_request mmap;
  } __attribute__((packed)) request;

  if (sdcg_shared_vm_start == NULL)
    sdcg_shared_vm_init();

  if (base == NULL) {
    base = sdcg_reserve(size);
    if (base == MAP_FAILED)
      return base;
  } else if ((uint8_t*)base < sdcg_shared_vm_start ||
             (uint8_t*)base + size >= sdcg_shared_vm_end) {
    V8_Fatal(__FILE__, __LINE__, 
             "SIM mmap overflow: base %p, size %x, current %p", 
             base, size, sdcg_shared_vm_start);
    return MAP_FAILED;
  }

  if (prot & PROT_EXEC) {
    if (sdcg_mode == 1) {
      V8_Fatal(__FILE__, __LINE__, "exec mem should never be mapped in sandbox");
    } else if (sdcg_mode == 2) {
      prot = PROT_READ|PROT_WRITE;
      prot_sim = PROT_READ|PROT_EXEC|SDCG_PROT_WRITE; //FIXME
    }
  }

  if (syscall(__NR_mprotect, base, size, prot) == -1) {
    V8_Fatal(__FILE__, __LINE__, "mprotect failed");
    return MAP_FAILED;
  }

  if (sdcg_mode == 2) { //SDCG_PROCESS
    secure_mem->_cc._ci.func_num = __NR_mmap;
    secure_mem->_cc._ci.arg1 = base;
    *(size_t*)(&secure_mem->_cc._ci.arg2) = size;
    *(int*)(&secure_mem->_cc._ci.arg3) = prot_sim;

    syscall(__NR_write, thread_fd_pub, &magic, sizeof(magic));
    syscall(__NR_read, thread_fd_pub, &magic, sizeof(magic));
  
    UpdateAllocatedSpaceLimits(base, size);
  } else if (sdcg_mode == 1) { //SANDBOX_PROCESS
    request.header.funcn = SDCG_MMAP;
    request.mmap.base = base;
    request.mmap.size = size;
    request.mmap.prot = prot;

    sdcg_send_request(&request, sizeof(request), &rbase, sizeof(rbase), false);

    if (rbase != base) {
      V8_Fatal(__FILE__, __LINE__, "rbase != base");
    }
  
    UpdateAllocatedSpaceLimits(base, size);
  }

  return base;
}

void* sdcg_unmap(void* base, size_t size) {
  int magic = __NR_mmap;
  void* rbase;
  struct {
    struct request_header header;
    struct mmap_request mmap;
  } __attribute__((packed)) request;

  return base;

  if ((uint8_t*)base < sdcg_shared_vm_start ||
      (uint8_t*)base + size >= sdcg_shared_vm_current) {
    V8_Fatal(__FILE__, __LINE__, "SIM unmap overflow");
    return MAP_FAILED;
  }

  if (syscall(__NR_mprotect, base, size, PROT_NONE) == -1) {
    V8_Fatal(__FILE__, __LINE__, "mprotect failed");
    return MAP_FAILED;
  }

  if (sdcg_mode == 2) { //SDCG_PROCESS
    secure_mem->_cc._ci.func_num = __NR_mmap;
    secure_mem->_cc._ci.arg1 = base;
    secure_mem->_cc._ci.arg2 = (void*)size;
    *((int*)(&secure_mem->_cc._ci.arg3)) = PROT_NONE;

    syscall(__NR_write, thread_fd_pub, &magic, sizeof(magic));
    syscall(__NR_read, thread_fd_pub, &magic, sizeof(magic));
  } else if (sdcg_mode == 1) { //SANDBOX_PROCESS
    request.header.funcn = SDCG_MMAP;
    request.mmap.base = base;
    request.mmap.size = size;
    request.mmap.prot = PROT_NONE;

    sdcg_send_request(&request, sizeof(request), &rbase, sizeof(rbase), false);

    if (rbase != base) {
      V8_Fatal(__FILE__, __LINE__, "rbase != base");
    }
  }

  return base;
}

static inline void handle_mmap() {
  struct mmap_request request;
  void* base;
  size_t size;
  int prot;

  SDCG_GET_REQUEST();

  base = request.base;
  size = request.size;
  prot = request.prot;

  if ((uint8_t*)base < sdcg_shared_vm_start ||
      (uint8_t*)base + size >= sdcg_shared_vm_end) {
    V8_Fatal(__FILE__, __LINE__, "overflow");
    base = MAP_FAILED;
  }

  if (prot != PROT_NONE)
    prot = PROT_READ | PROT_WRITE;

  if (syscall(__NR_mprotect, base, size, prot) == -1) {
    V8_Fatal(__FILE__, __LINE__, "mprotect failed");
    base = MAP_FAILED;
  }

  UpdateAllocatedSpaceLimits(base, size);

  sdcg_return(&base, sizeof(base));
}

void sdcg_prepare_for_mark_compact(PagedSpace *space) {
  int dummy;
  struct {
    struct request_header header;
    PagedSpace *space;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_PREPARE_FOR_MARK_COMPACT;
  request.space = space;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_prepare_for_mark_compact() {
  struct {
    PagedSpace* space;
  } __attribute__((packed)) request;
  int dummy = 0;

  SDCG_GET_REQUEST();

  request.space->PrepareForMarkCompact();

  sdcg_return(&dummy, sizeof(dummy));
}

struct mcv_request {
  Map* map;
  HeapObject *obj;
} __attribute__((packed));

void sdcg_mark_compact_visit(Map* map, HeapObject *obj) {
  int dummy;
  struct {
    struct request_header header;
    struct mcv_request mcv;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_MARK_COMPACT_VISIT;
  request.mcv.map = map;
  request.mcv.obj = obj;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

extern void sdcg_mark_compact_visit_proxy(Map* map, HeapObject* obj);
static void handle_mark_compact_visit() {
  struct mcv_request request;
  int dummy = 0;

  SDCG_GET_REQUEST();

  sdcg_mark_compact_visit_proxy(request.map, request.obj);

  sdcg_return(&dummy, sizeof(dummy));
}

void sdcg_empty_marking_deque(MarkCompactCollector* collector) {
  int dummy;
  struct {
    struct request_header header;
    MarkCompactCollector* collector;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_EMPTY_MARKING_DEQUE;
  request.collector = collector;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_empty_marking_deque() {
  int dummy = 0;
  struct {
    MarkCompactCollector* collector;
  } __attribute__((packed)) request;

  SDCG_GET_REQUEST();

  request.collector->EmptyMarkingDeque();

  sdcg_return(&dummy, sizeof(dummy));
}

struct sweep_code_space_request {
  MarkCompactCollector* mc;
  PagedSpace* space;
} __attribute__((packed));

void sdcg_sweep_code_space(MarkCompactCollector* mc, PagedSpace* space) {
  int dummy;
  struct {
    struct request_header header;
    struct sweep_code_space_request scs;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_SWEEP_CODE_SPACE;
  request.scs.mc = mc;
  request.scs.space = space;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_sweep_code_space() {
  struct sweep_code_space_request request;
  int dummy = 0;

  SDCG_GET_REQUEST();

  request.mc->sdcg_sweep_code_space_proxy(request.space);

  sdcg_return(&dummy, sizeof(dummy));
}

struct make_code_request {
  CompilationInfo* info;
  Zone* zone;
} __attribute__((packed));

bool sdcg_make_code(CompilationInfo* info, bool crankshaft) {
  bool result;
  Zone* zone = info->zone();
  struct {
    struct request_header header;
    struct make_code_request mcr;
  } __attribute__ ((packed)) request;

  request.header.funcn = SDCG_MAKE_CODE;
  request.mcr.info = info;
  request.mcr.zone = zone;

  //sdcg_mutex->Lock();

  memcpy(secure_mem->scratch_page, info, sizeof(CompilationInfo));
  memcpy(secure_mem->scratch_page + sizeof(CompilationInfo), zone, sizeof(Zone));

  sdcg_send_request(&request, sizeof(request), &result, sizeof(result), false, false);

  memcpy(info, secure_mem->scratch_page, sizeof(CompilationInfo));
  memcpy(zone, secure_mem->scratch_page + sizeof(CompilationInfo), sizeof(Zone));

  //sdcg_mutex->Unlock();

  return result;
}

static void handle_make_code() {
  bool result;
  struct make_code_request request;

  SDCG_GET_REQUEST();
  CompilationInfo* info = request.info;
  Zone* zone = request.zone;

  memcpy(info, secure_mem->scratch_page, sizeof(CompilationInfo));
  memcpy(zone, secure_mem->scratch_page + sizeof(CompilationInfo), sizeof(Zone));

  result = FullCodeGenerator::MakeCode(info);

  memcpy(secure_mem->scratch_page, info, sizeof(CompilationInfo));
  memcpy(secure_mem->scratch_page + sizeof(CompilationInfo), zone, sizeof(Zone));

  sdcg_return(&result, sizeof(result));
}

void sdcg_active_code(Code* code) {
  int dummy;
  struct {
    struct request_header header;
    Code* code;
  } __attribute__((packed)) request;

  return code->GetHeap()->incremental_marking()->ActivateGeneratedStub(code);

  request.header.funcn = SDCG_ACTIVE_CODE;
  request.code = code;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_active_code() {
  int dummy = 0;
  struct {
    Code* code;
  } __attribute__((packed)) request;

  SDCG_GET_REQUEST();

  request.code->GetHeap()->incremental_marking()->ActivateGeneratedStub(request.code);

  sdcg_return(&dummy, sizeof(dummy));
}

struct copy_code_request {
  Heap* heap;
  Code* code;
  Vector<byte> *reloc_info;
} __attribute__((packed));

MaybeObject* sdcg_copy_code(Heap *heap, Code *code, Vector<byte> *reloc_info) {
  MaybeObject* result;
  struct {
    struct request_header header;
    struct copy_code_request ccr;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_COPY_CODE;
  request.ccr.heap = heap;
  request.ccr.code = code;
  request.ccr.reloc_info = reloc_info;

  sdcg_send_request(&request, sizeof(request), &result, sizeof(result), false);

  return result;
}

static void handle_copy_code() {
  MaybeObject* result;
  struct copy_code_request request;

  SDCG_GET_REQUEST();
  Heap* heap = request.heap;
  Code* code = request.code;
  Vector<byte>* reloc_info = request.reloc_info;

  if (reloc_info == NULL) {
    result = heap->CopyCode(code);
  } else {
    result = heap->CopyCode(code, *reloc_info);
  }

  sdcg_return(&result, sizeof(result));
}

struct new_code_request {
  Isolate* isolate;
  CodeDesc* desc;
  uint32_t flags;
  bool immovable;
  bool crankshaft;
} __attribute__((packed));

Handle<Code> sdcg_new_code(Isolate* isolate, CodeDesc* desc, 
                          uint32_t flags, Handle<Object> self_ref,
                          bool immovable, bool crankshaft) {
  Code *result;
  struct {
    struct request_header header;
    struct new_code_request new_code;
  } __attribute__((packed)) request;

  uint8_t* stack_base = (uint8_t*)(desc->origin) + sizeof(Assembler);
  if ((uint8_t*)desc > stack_base)
    stack_base = (uint8_t*)desc;
  if (stack_base > sdcg_stack_base)
    sdcg_stack_base = stack_base;
  request.header.funcn = SDCG_NEW_CODE;
  request.new_code.isolate = isolate;
  request.new_code.desc = desc;
  request.new_code.flags = flags;
  request.new_code.immovable = immovable;
  request.new_code.crankshaft = crankshaft;

  sdcg_send_request(&request, sizeof(request), &result, sizeof(result), true);

  if (!self_ref.is_null()) {
    *(self_ref.location()) = result;
  }

  memcpy(desc->origin, secure_mem->scratch_page, sizeof(Assembler));

  return Handle<Code>(result);
}

static void handle_new_code() {
  struct new_code_request request;
  CodeDesc* desc;

  SDCG_GET_REQUEST();

  desc = request.desc;
  Handle<Object> self_ref;
  Handle<Code> code = request.isolate->factory()->NewCode(*(desc), request.flags, self_ref,
                                                          request.immovable, request.crankshaft);

  memcpy(secure_mem->scratch_page, desc->origin, sizeof(Assembler));

  sdcg_return(code.location(), sizeof(Code*));
}

struct finish_code_request {
  CodeStub* code_stub;
  Code* code;
  Isolate* isolate;
}  __attribute__((packed));

void sdcg_finish_code(CodeStub* code_stub, Handle<Code> code, Isolate* isolate) {
  int dummy;
  struct {
    struct request_header header;
    struct finish_code_request fcr;
  }  __attribute__((packed)) request;

  uint8_t* stack_base = (uint8_t*)code_stub + sizeof(BinaryOpStub);
  if (stack_base > sdcg_stack_base)
    sdcg_stack_base = stack_base;
  request.header.funcn = SDCG_FINISH_CODE;
  request.fcr.code_stub = code_stub;
  request.fcr.code = *code;
  request.fcr.isolate = isolate;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), true);
}

static void handle_finish_code() {
  int dummy = 0;
  struct finish_code_request request;

  SDCG_GET_REQUEST();
  CodeStub* code_stub = request.code_stub;
  Handle<Code> code(request.code, request.isolate); 

  code->set_major_key(code_stub->MajorKey());
  code_stub->FinishCode(code);

  sdcg_return(&dummy, sizeof(dummy));
}

struct patch_inline_smi_request {
  Address address;
  InlinedSmiCheck check;
}  __attribute__((packed));

void sdcg_patch_inline_smi_code(Address address, InlinedSmiCheck check) {
  int dummy;
  struct {
    struct request_header header;
    struct patch_inline_smi_request pisr;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_PATCH_INLINE_SMI_CODE;
  request.pisr.address = address;
  request.pisr.check = check;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_patch_inline_smi_code() {
  int dummy = 0;
  struct patch_inline_smi_request request;

  SDCG_GET_REQUEST();
  Address address = request.address;
  InlinedSmiCheck check = request.check;

  PatchInlinedSmiCode(address, check);

  sdcg_return(&dummy, sizeof(dummy));
}

struct patch_interrupt_code_request {
  Code* unoptimized_code;
  Code* interrupt_code;
  Code* replacement_code;
} __attribute__((packed));

void sdcg_patch_interrupt_code(Code* unoptimized_code, Code* interrupt_code,
                              Code* replacement_code) {
  int dummy;
  struct {
    struct request_header header;
    struct patch_interrupt_code_request pic;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_PATCH_INTERRUPT_CODE;
  request.pic.unoptimized_code = unoptimized_code;
  request.pic.interrupt_code = interrupt_code;
  request.pic.replacement_code = replacement_code;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_patch_interrupt_code() {
  int dummy = 0;
  struct patch_interrupt_code_request request;

  SDCG_GET_REQUEST();
  Code* unoptimized_code = request.unoptimized_code;
  Code* interrupt_code = request.interrupt_code;
  Code* replacement_code = request.replacement_code;

  Deoptimizer::PatchInterruptCode(unoptimized_code, interrupt_code, replacement_code);
  
  sdcg_return(&dummy, sizeof(dummy));
}

void sdcg_revert_interrupt_code(Code* unoptimized_code, Code* interrupt_code,
                               Code* replacement_code) {
  int dummy;
  struct {
    struct request_header header;
    struct patch_interrupt_code_request pic;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_REVERT_INTERRUPT_CODE;
  request.pic.unoptimized_code = unoptimized_code;
  request.pic.interrupt_code = interrupt_code;
  request.pic.replacement_code = replacement_code;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_revert_interrupt_code() {
  int dummy = 0;
  struct patch_interrupt_code_request request;

  SDCG_GET_REQUEST();
  Code* unoptimized_code = request.unoptimized_code;
  Code* interrupt_code = request.interrupt_code;
  Code* replacement_code = request.replacement_code;

  Deoptimizer::RevertInterruptCode(unoptimized_code, interrupt_code, replacement_code);
  
  sdcg_return(&dummy, sizeof(dummy));
}

void sdcg_set_target_object(RelocInfo* info, Object* replace_with) {
  int dummy;
  struct request_header request;
  void** addrs = (void**)(secure_mem->scratch_page);

  request.funcn = SDCG_SET_TARGET_OBJECT;
  addrs[0] = replace_with;

  //sdcg_mutex->Lock();
  memcpy(&addrs[1], info, sizeof(*info));

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false, false);

  //sdcg_mutex->Unlock();
}

static void handle_set_target_object() {
  int dummy = 0;
  void** addrs = (void**)(secure_mem->scratch_page);
  Object* obj = (Object*)addrs[0];
  RelocInfo* info = (RelocInfo*)(&addrs[1]);

  info->set_target_object(obj);

  sdcg_return(&dummy, sizeof(dummy));
}

struct ic_miss_request {
  Arguments *args;
  Isolate *isolate;
  SDCG_IC_CALL reason;
} __attribute__((packed));

MaybeObject* sdcg_ic_miss(Arguments *args, Isolate *isolate, SDCG_IC_CALL reason) {
  MaybeObject* result;
  struct {
    struct request_header header;
    struct ic_miss_request ic_miss;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_IC_MISS;
  request.ic_miss.args = args;
  request.ic_miss.isolate = isolate;
  request.ic_miss.reason = reason;

  sdcg_send_request(&request, sizeof(request), &result, sizeof(result), true);

  return result;
}

extern MaybeObject* __RT_impl_CallIC_Miss(Arguments args, Isolate* isolate);
extern MaybeObject* __RT_impl_LoadIC_Miss(Arguments args, Isolate* isolate);

static void handle_ic_miss() {
  struct ic_miss_request request;
  MaybeObject *result = NULL;

  SDCG_GET_REQUEST();

  switch (request.reason) {
  case CALL_MISS:
    result = __RT_impl_CallIC_Miss(*(request.args), request.isolate);
    break;

  case LOAD_MISS:
    result = __RT_impl_LoadIC_Miss(*(request.args), request.isolate);
    break;

  default:
    V8_Fatal(__FILE__, __LINE__, "unknown reason");
  }

  sdcg_return(&result, sizeof(result));
}

struct set_target_address_request {
  Address pc;
  Code* code;
}  __attribute__((packed));

void sdcg_set_target_address_at(Address pc, Code* code) {
  int dummy;
  struct {
    struct request_header header;
    struct set_target_address_request sta;
  }  __attribute__((packed)) request;

  request.header.funcn = SDCG_SET_TARGET_AT;
  request.sta.pc = pc;
  request.sta.code = code;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_set_target_address_at() {
  int dummy;
  struct set_target_address_request request;

  SDCG_GET_REQUEST();

  IC::SetTargetAtAddress(request.pc, request.code);

  sdcg_return(&dummy, sizeof(dummy));
}

struct copy_bytes_request {
  uint8_t* dst;
  uint8_t* src;
  size_t size;
}  __attribute__((packed));

void sdcg_copy_bytes(uint8_t* dst, uint8_t* src, size_t size) {
  int dummy;
  struct {
    struct request_header header;
    struct copy_bytes_request cbr;
  }  __attribute__((packed)) request;

  request.header.funcn = SDCG_COPY_BYTES;
  request.cbr.dst = dst;
  request.cbr.src = src;
  request.cbr.size = size;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_copy_bytes() {
  int dummy = 0;
  struct copy_bytes_request request;

  SDCG_GET_REQUEST();

  CopyBytes(request.dst, request.src, request.size);

  sdcg_return(&dummy, sizeof(dummy));
}

struct write_field_request {
  Code* code;
  int offset;
  void* value;
  int size;
}  __attribute__((packed));

void sdcg_write_field(Code* code, int offset, void* value, int size) {
  int dummy;
  struct {
    struct request_header header;
    struct write_field_request wfr;
  }  __attribute__((packed)) request;

  request.header.funcn = SDCG_WRITE_FIELD;
  request.wfr.code = code;
  request.wfr.offset = offset;
  request.wfr.value = value;
  request.wfr.size = size;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

void sdcg_write_field(Code* code, int offset, unsigned long value, int size) {
  int dummy;
  struct {
    struct request_header header;
    struct write_field_request wfr;
  }  __attribute__((packed)) request;

  request.header.funcn = SDCG_WRITE_FIELD;
  request.wfr.code = code;
  request.wfr.offset = offset;
  *(unsigned long*)(&request.wfr.value) = value;
  request.wfr.size = size;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

#define FIELD_ADDR(p, offset) \
  (reinterpret_cast<byte*>(p) + offset - kHeapObjectTag)

static void handle_write_field() {
  int dummy = 0;
  struct write_field_request request;

  SDCG_GET_REQUEST();
  Code* code = request.code;
  int offset = request.offset;
  int size = request.size;

  switch(size) {
  case BYTE:
    *reinterpret_cast<byte*>(FIELD_ADDR(code, offset)) = *(byte*)(&request.value);
    break;

  case INT:
    *reinterpret_cast<int*>(FIELD_ADDR(code, offset)) = *(int*)(&request.value);
    break;

  case UINT32:
    *reinterpret_cast<uint32_t*>(FIELD_ADDR(code, offset)) = *(uint32_t*)(&request.value);
    break;

  case OBJECT:
    *reinterpret_cast<Object**>(FIELD_ADDR(code, offset)) = (Object*)request.value;
    break;

  default:
    V8_Fatal(__FILE__, __LINE__, "invalid size %d", size);
    break;
  }

  sdcg_return(&dummy, sizeof(dummy));
}

struct make_code_epilogue_request {
  MacroAssembler* masm;
  CompilationInfo* info;
  LCodeGen* cgen;
} __attribute__((packed));

Handle<Code> sdcg_make_code_epilogue(MacroAssembler* masm,
                                    CompilationInfo* info,
                                    LCodeGen* cgen) {
  Code* code;
  struct {
    struct request_header header;
    struct make_code_epilogue_request mce;
  }  __attribute__((packed)) request;

  uint8_t* stack_base = (uint8_t*)(info->code_stub()) + sizeof(ToBooleanStub);
  if (stack_base > sdcg_stack_base)
    sdcg_stack_base = stack_base;
  request.header.funcn = SDCG_MAKE_CODE_EPILOGUE;
  request.mce.masm = masm;
  request.mce.info = info;
  request.mce.cgen = cgen;

  sdcg_send_request(&request, sizeof(request), &code, sizeof(code), true);

  return Handle<Code>(code, info->isolate());
}

static void handle_make_code_epilogue() {
  Handle<Code> code;
  Code *raw;
  struct make_code_epilogue_request request;

  SDCG_GET_REQUEST();
  MacroAssembler* masm = request.masm;
  CompilationInfo* info = request.info;
  LCodeGen* cgen = request.cgen;

  code = CodeGenerator::MakeCodeEpilogue(masm, info->flags(), info);
  cgen->FinishCode(code);
  code->set_is_crankshafted(true);

  raw = *code;
  sdcg_return(&raw, sizeof(raw));
}

struct patch_incremental_marking_request {
  Heap* heap;
  RecordWriteStub::Mode mode;
} __attribute__((packed));

void sdcg_patch_incremental_marking(Heap* heap, RecordWriteStub::Mode mode) {
  int dummy;
  struct {
    struct request_header header;
    struct patch_incremental_marking_request pim;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_PATCH_INCREMENTAL_MARKING;
  request.pim.heap = heap;
  request.pim.mode = mode;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

extern void PatchIncrementalMarkingRecordWriteStubs(Heap* heap, RecordWriteStub::Mode mode);

static void handle_patch_incremental_marking() {
  int dummy = 0;
  struct patch_incremental_marking_request request;

  SDCG_GET_REQUEST();

  PatchIncrementalMarkingRecordWriteStubs(request.heap, request.mode);

  sdcg_return(&dummy, sizeof(dummy));
}

struct process_marking_queue_request {
  IncrementalMarking* incremental_marking;
  intptr_t bytes_to_process;
} __attribute__((packed));

void sdcg_process_marking_queue(IncrementalMarking* incremental_marking, intptr_t bytes_to_process) {
  int dummy;
  struct {
    struct request_header header;
    struct process_marking_queue_request pmq;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_PROCESS_MARKING_QUEUE;
  request.pmq.incremental_marking = incremental_marking;
  request.pmq.bytes_to_process = bytes_to_process;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_process_marking_queue() {
  int dummy = 0;
  struct process_marking_queue_request request;

  SDCG_GET_REQUEST();
  IncrementalMarking* incremental_marking = request.incremental_marking;

  incremental_marking->ProcessMarkingDeque(request.bytes_to_process);

  sdcg_return(&dummy, sizeof(dummy));
}

struct patch_code_age_request {
  byte* sequence;
  Code::Age age;
  MarkingParity parity;
} __attribute__((packed));

void sdcg_patch_code_age(byte* sequence, Code::Age age, MarkingParity parity) {
  int dummy;
  struct {
    struct request_header header;
    struct patch_code_age_request pca;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_PATCH_CODE_AGE;
  request.pca.sequence = sequence;
  request.pca.age = age;
  request.pca.parity = parity;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_patch_code_age() {
  int dummy = 0;
  struct patch_code_age_request request;

  SDCG_GET_REQUEST();

  Code::PatchPlatformCodeAge(request.sequence, request.age, request.parity);

  sdcg_return(&dummy, sizeof(dummy));
}

struct patch_record_write_stub_request {
  Code* stub;
  RecordWriteStub::Mode mode;
} __attribute__((packed));

void sdcg_patch_record_write_stub(Code* stub, RecordWriteStub::Mode mode) {
  int dummy;
  struct {
    struct request_header header;
    struct patch_record_write_stub_request prws;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_PATCH_RECORD_WRITE_STUB;
  request.prws.stub = stub;
  request.prws.mode = mode;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_patch_record_write_stub() {
  int dummy = 0;
  struct patch_record_write_stub_request request;

  SDCG_GET_REQUEST();

  RecordWriteStub::Patch(request.stub, request.mode);

  sdcg_return(&dummy, sizeof(dummy));
}

struct evacuate_live_objects_request {
  MarkCompactCollector* collector;
  Page* page;
} __attribute__((packed));

void sdcg_evacuate_live_objects(MarkCompactCollector* collector, Page* page) {
  int dummy;
  struct {
    struct request_header header;
    struct evacuate_live_objects_request elo;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_EVACUATE_LIVE_OBJECTS;
  request.elo.collector = collector;
  request.elo.page = page;

  sdcg_send_request(&request, sizeof(request), &dummy, sizeof(dummy), false);
}

static void handle_evacuate_live_objects() {
  int dummy = 0;
  struct evacuate_live_objects_request request;

  SDCG_GET_REQUEST();
  MarkCompactCollector* collector = request.collector;

  collector->EvacuateLiveObjectsFromPage(request.page);

  sdcg_return(&dummy, sizeof(dummy));
}

struct regexp_compile_request {
  JSRegExp* regexp;
  String* subject;
  bool is_ascii;
  Isolate* isolate;
} __attribute__((packed));

bool sdcg_regexp_compile(Handle<JSRegExp> regexp, Handle<String> subject, 
                        bool is_ascii, Isolate* isolate) {
  bool result;
  struct {
    struct request_header header;
    struct regexp_compile_request rcr;
  } __attribute__((packed)) request;

  request.header.funcn = SDCG_REGEXP_COMPILE;
  request.rcr.regexp = *regexp;
  request.rcr.subject = *subject;
  request.rcr.is_ascii = is_ascii;
  request.rcr.isolate = isolate;

  sdcg_send_request(&request, sizeof(request), &result, sizeof(result), false);

  return result;
}

static void handle_regexp_compile() {
  bool result;
  struct regexp_compile_request request;

  SDCG_GET_REQUEST();

  Handle<JSRegExp> regexp(request.regexp, request.isolate);
  Handle<String> subject(request.subject, request.isolate);

  result = RegExpImpl::CompileIrregexp(regexp, subject, request.is_ascii);

  sdcg_return(&result, sizeof(result));
}

void sdcg_protect(void) {
  FILE* map_file;
  char line[80];
  int truncated;
  unsigned long start, stop;
  char *ptr;
  bool writable;

  map_file = fopen("/proc/self/maps", "r");
  if (map_file == NULL) {
    V8_Fatal(__FILE__, __LINE__, "sdcg_protect: failed to open /proc/self/maps");
  }

  for (truncated = 0;;) {
    if (fgets(line, sizeof(line), map_file) == NULL) {
      if (feof(map_file) || errno != EINTR) {
        break;
      }
      continue;
    }
    if (!truncated) {
      ptr = line;
      errno = 0;
      start = strtoul(ptr, &ptr, 16);
      if (errno || *ptr++ != '-') {
        V8_Fatal(__FILE__, __LINE__, "sdcg_protect: failed to parse /proc/self/maps");
      }
      stop = strtoul(ptr, &ptr, 16);
      if (errno || *ptr++ != ' ') {
        V8_Fatal(__FILE__, __LINE__, "sdcg_protect: failed to parse /proc/self/maps");
      }

      if (*ptr++ == 'r') {
        //readable = true;
      }
      if (*ptr++ == 'w') {
        writable = true;
      }
      if (*ptr++ == 'x') {
        if (writable)
          mprotect((void *)start, stop-start, PROT_READ|PROT_EXEC|SDCG_PROT_WRITE); //FIXME
      }
    }
    truncated = (strchr(line, '\n') == NULL ? 1 : 0);
  }
  fclose(map_file);
}

void sdcg_dispatch_cmd(request_header *header) {
  uint8_t* rsp = NULL;
  size_t ss;

  if (header->funcn > MAX_FUNCN) {
    V8_Fatal(__FILE__, __LINE__, "unknown callback function number");
  }

  if (header->funcn == SDCG_MMAP) {
    handle_mmap();
    return;
  } else if (header->funcn == SDCG_RESERVE) {
    handle_reserve();
    return;
  }

  rsp = secure_mem->_stack_info.stack_top;
  ss = secure_mem->_stack_info.stack_size;
  memcpy(rsp, secure_mem->stack + sizeof(rsp) + sizeof(ss), ss);

  switch (header->funcn) {
    case SDCG_PREPARE_FOR_MARK_COMPACT:
      handle_prepare_for_mark_compact();
      break;

    case SDCG_MARK_COMPACT_VISIT:
      handle_mark_compact_visit();
      break;

    case SDCG_SWEEP_CODE_SPACE:
      handle_sweep_code_space();
      break;

    case SDCG_MAKE_CODE:
      handle_make_code();
      break;

    case SDCG_ACTIVE_CODE:
      handle_active_code();
      break;

    case SDCG_COPY_CODE:
      handle_copy_code();
      break;

    case SDCG_NEW_CODE:
      handle_new_code();
      break;

    case SDCG_COPY_BYTES:
      handle_copy_bytes();
      break;

    case SDCG_PATCH_INLINE_SMI_CODE:
      handle_patch_inline_smi_code();
      break;

    case SDCG_PATCH_INTERRUPT_CODE:
      handle_patch_interrupt_code();
      break;

    case SDCG_REVERT_INTERRUPT_CODE:
      handle_revert_interrupt_code();
      break;

    case SDCG_FINISH_CODE:
      handle_finish_code();
      break;

    case SDCG_MAKE_CODE_EPILOGUE:
      handle_make_code_epilogue();
      break;

    case SDCG_IC_MISS:
      handle_ic_miss();
      break;

    case SDCG_SET_TARGET_AT:
      handle_set_target_address_at();
      break;

    case SDCG_WRITE_FIELD:
      handle_write_field();
      break;

    case SDCG_SET_TARGET_OBJECT:
      handle_set_target_object();
      break;

    case SDCG_PATCH_INCREMENTAL_MARKING:
      handle_patch_incremental_marking();
      break;

    case SDCG_PROCESS_MARKING_QUEUE:
      handle_process_marking_queue();
      break;

    case SDCG_PATCH_CODE_AGE:
      handle_patch_code_age();
      break;

    case SDCG_PATCH_RECORD_WRITE_STUB:
      handle_patch_record_write_stub();
      break;

    case SDCG_EVACUATE_LIVE_OBJECTS:
      handle_evacuate_live_objects();
      break;

    case SDCG_REGEXP_COMPILE:
      handle_regexp_compile();
      break;

    case SDCG_EMPTY_MARKING_DEQUE:
      handle_empty_marking_deque();
      break;

    default:
      break;
  }
}

int sdcg_start_trusted_process(void* args) {
  struct request_header header;
  int rc;
  int fd;
  uintptr_t limit = reinterpret_cast<uintptr_t>(&limit) - FLAG_stack_size * KB;

  if (args != NULL) {
    for (fd = sysconf(_SC_OPEN_MAX); --fd > 2; ) {
      if (fd != process_fd_pub && fd != thread_fd_pub) {
        syscall(__NR_close, fd);
      }
    }

    sdcg_mode = 2;
  }
  Isolate::Current()->stack_guard()->SetStackLimit(limit);

  for(;;) {

    if ((rc = syscall(__NR_read, process_fd_pub, &header, sizeof(header))) != sizeof(header)) {
      if (rc) {
        syscall(__NR_exit, 0);
        //V8_Fatal(__FILE__, __LINE__, 
        //         "failed to read callback function and thread id %d (shouldbe %d): %s", 
        //         rc, sizeof(header), strerror(errno));
      }
#ifdef __NR_exit_group
      syscall(__NR_exit_group, 0);
#else
      syscall(__NR_exit, 0);
#endif
    }

    sdcg_dispatch_cmd(&header);
  }
#ifdef __NR_exit_group
  syscall(__NR_exit_group, 1);
#else
  syscall(__NR_exit, 1);
#endif

  return 2;
}
#endif

static void sdcg_create_trusted_process() {
  secure_mem = (struct sdcg_secure_mem*)syscall(NR_MMAP, OS::GetRandomMmapAddr(), 
                                               8*KB + 16*KB, PROT_READ|PROT_WRITE, 
                                               MAP_SHARED|MAP_ANONYMOUS, -1, 0);

  if (secure_mem == MAP_FAILED) {
    V8_Fatal(__FILE__, __LINE__, "failed to allocate IPC buffer area %s", strerror(errno));
  }

  void* stack = (void*)syscall(NR_MMAP, NULL, 0x21000,
                         PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS/*|MAP_GROWSDOWN*/,
                         -1, 0);

  pid_t pid = clone(sdcg_start_trusted_process, (uint8_t*)stack + 0x21000, SIGCHLD, &pid);
  //pid = fork();
  if (pid < 0) {
    V8_Fatal(__FILE__, __LINE__, "failed to fork trusted process %s", strerror(errno));
  }

  mprotect(secure_mem, 8192, PROT_NONE);
  close(process_fd_pub);
  close(thread_fd_pub);
}

extern void sdcg_start_trusted_thread(unsigned char* secure_mem);

static int sdcg_trusted_thread(void* args) {
  struct sdcg_secure_mem *secure_mem = (struct sdcg_secure_mem*)args;
  int rc, ret;
  int magic;

  void* addr;
  size_t size;
  int prot;

  if (secure_mem == NULL) {
    syscall(__NR_exit, -1);
  }

  //fprintf(stderr, "trusted thread started\n");

  for(;;) {
    if ((rc = syscall(__NR_read, thread_fd, &magic, sizeof(magic))) != sizeof(magic)) {
      if (rc) {
        V8_Fatal(__FILE__, __LINE__, "failed to read syscall number %d (shouldbe %d)", 
                 rc, sizeof(magic));
      }
      syscall(__NR_write, "trusted thread exited\n", 22);
      syscall(__NR_exit, 0);
    }

    switch (magic) {
    case __NR_mmap:
    case __NR_mprotect:
      addr = secure_mem->_cc._ci.arg1;
      size = *(size_t*)(&secure_mem->_cc._ci.arg2);
      prot = *(int*)(&secure_mem->_cc._ci.arg3);

      ret = syscall(__NR_mprotect, addr, size, prot);
  
      UpdateAllocatedSpaceLimits(addr, size);

      syscall(__NR_write, thread_fd, &ret, sizeof(ret));
      break;

    case __NR_munmap:
      addr = secure_mem->_cc._ci.arg1;
      if (addr < sdcg_shared_vm_current) {
        V8_Fatal(__FILE__, __LINE__, "new current is less than old");
      }
      
      sdcg_shared_vm_current = (uint8_t*)addr;
      syscall(__NR_write, thread_fd, &magic, sizeof(magic));
      break;

    default:
      V8_Fatal(__FILE__, __LINE__, "Invalid syscall number %d", magic);
      break;
    }
  }

  syscall(__NR_write, "trusted thread exited\n", 22);
  return 0;
}

void sdcg_create_trusted_thread(struct sdcg_secure_mem* secure_mem) {
  void* stack = (void*)syscall(NR_MMAP, NULL, 4096,
                               PROT_READ|PROT_WRITE,
                               MAP_PRIVATE|MAP_ANONYMOUS/*|MAP_GROWSDOWN*/,
                               -1, 0);

  void* mem = secure_mem;
  if (mprotect(mem, 4096, PROT_READ)) {
    V8_Fatal(__FILE__, __LINE__, 
             "Failed to set permission for secure_mem(1): %s", strerror(errno));
  }

  if (mprotect((uint8_t*)mem+4096, 4096, PROT_READ|PROT_WRITE)) {
    V8_Fatal(__FILE__, __LINE__, "Failed to set permission for secure_mem(2): %s", strerror(errno));
  }

  //create the thread
  int tid = clone(sdcg_trusted_thread, (uint8_t*)stack + 4096,
              CLONE_VM|CLONE_FS|CLONE_FILES|CLONE_SIGHAND|CLONE_THREAD|CLONE_SYSVSEM|CLONE_UNTRACED,
              secure_mem);

  if (tid == -1) {
    V8_Fatal(__FILE__, __LINE__, "Failed to create memory sync thread %s", strerror(errno));
  }
}

void sdcg_enable_sandbox() {
  int pair[4];

  if (sdcg_mode)
    return;

  if (socketpair(AF_UNIX, SOCK_STREAM, 0, pair) ||
      socketpair(AF_UNIX, SOCK_STREAM, 0, pair+2)) {
    V8_Fatal(__FILE__, __LINE__, "failed to allocate socket for communication %s", strerror(errno));
  }

  process_fd = pair[0];
  process_fd_pub = pair[1];
  thread_fd = pair[2];
  thread_fd_pub = pair[3];

  sdcg_create_trusted_process();

  sdcg_create_trusted_thread(secure_mem);

  sdcg_protect();
  sdcg_mode = 1;
}

} }  // namespace v8::internal
