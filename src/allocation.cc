// Copyright 2012 the V8 project authors. All rights reserved.
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

#include "allocation.h"

#include <stdlib.h>  // For free, malloc.
#include "checks.h"
#include "platform.h"
#include "utils.h"
#ifdef SEC_DYN_CODE_GEN
#include <unistd.h>
#include <pthread.h>
#endif

namespace v8 {
namespace internal {

// FIXME: this should be replaced if possible
// this is a customer heap on top of the shared memory pool
// I implemented this to avoid marshalling/unmarshalling during RPC
// but it's too simple, just suitable for PoC
//
#ifdef SEC_DYN_CODE_GEN
struct sdcg_mm_t {
  size_t size;
  struct sdcg_mm_t* next;
  struct sdcg_mm_t* prev;
};

struct sdcg_heap_t {
  sdcg_mm_t* freelist[9];
  size_t size;
  byte* base;
  byte* current;
  byte* end;
  pthread_mutex_t mutex;
};

static sdcg_heap_t *sdcg_heap;

static int get_index(size_t needed) {
  int index = 0;
  size_t memory = 16;
  while (memory < needed) {
    memory *= 2;
    index++;
  }

  return index > 8 ? 8 : index;
}

static void* offset_pointer(void* ptr, int offset) {
  byte* offset_ptr = (byte *) ptr;
  if (offset) return offset_ptr + sizeof(sdcg_mm_t);
  else return offset_ptr - sizeof(sdcg_mm_t);
}

static void* sdcg_malloc(size_t size) {
  size_t needed = 0;

  if (sdcg_heap == NULL) {
    needed = RoundUp(128*MB + sizeof(sdcg_heap_t), 4096);

    sdcg_heap = (sdcg_heap_t*)sdcg_mmap(NULL, needed, 3);  
    if (sdcg_heap == NULL) {
      return NULL;
    }

    for (int i = 0; i < 9; i++) {
      sdcg_heap->freelist[i] = NULL;
    }
    sdcg_heap->size = needed - sizeof(sdcg_heap_t);
    sdcg_heap->current = sdcg_heap->base = (byte*)sdcg_heap + sizeof(sdcg_heap_t);
    sdcg_heap->end = sdcg_heap->base + sdcg_heap->size;

    pthread_mutexattr_t attr;
    memset(&attr, 0, sizeof(attr));
    int result = pthread_mutexattr_init(&attr);
    ASSERT(result == 0);
    result = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    ASSERT(result == 0);
    result = pthread_mutex_init(&sdcg_heap->mutex, &attr);
    ASSERT(result == 0);
    result = pthread_mutexattr_destroy(&attr);
    ASSERT(result == 0);
    USE(result);
  }

  needed = size + sizeof(sdcg_mm_t);
  int target = get_index(needed);
  
  sdcg_mm_t *front, *next;

  pthread_mutex_lock(&sdcg_heap->mutex);

  if (target < 8) {
    // for small chunk, search target bucket first
    for (int index = target; index < 8; ++index) {
      if (sdcg_heap->freelist[index]) {
        front = sdcg_heap->freelist[index];
        next = front->next;

        front->next = NULL;
        front->prev = NULL;

        if (next) {
          next->prev = NULL;
          sdcg_heap->freelist[index] = next;
        } else {
          sdcg_heap->freelist[index] = NULL;
        }

        pthread_mutex_unlock(&sdcg_heap->mutex);
        return offset_pointer(front, 1);
      }
    }
  } else {
    // for large chunk, search large chunk list
    for (front = sdcg_heap->freelist[target]; front != NULL; front = front->next) {
      if (front->size > needed) {
        next = front->next;
        
        if (front->prev)
          front->prev->next = next;
        else
          sdcg_heap->freelist[target] = next;

        if (next)
          next->prev = front->prev;

        front->next = NULL;
        front->prev = NULL;

        pthread_mutex_unlock(&sdcg_heap->mutex);
        return offset_pointer(front, 1);
      }
    }
  }

  if (needed > 2048) {
    needed = RoundUp(needed, 4096);
    
front = (sdcg_mm_t*)sdcg_mmap(NULL, needed, 3);  
    if (front == NULL) {
      pthread_mutex_unlock(&sdcg_heap->mutex);
      return NULL;
    }

    front->size = needed;
    front->next = NULL;
    front->prev = NULL;

    pthread_mutex_unlock(&sdcg_heap->mutex);
    return offset_pointer(front, 1);
  }

  needed = RoundUp(needed, 1 << (target + 4));
  if (sdcg_heap->current + needed > sdcg_heap->end) {
    V8_Fatal(__FILE__, __LINE__, "not enough mem\n");
    return NULL;
  }

  front = (sdcg_mm_t*)sdcg_heap->current;
  front->size = needed;
  front->next = NULL;
  front->prev = NULL;

  sdcg_heap->current += needed;

  pthread_mutex_unlock(&sdcg_heap->mutex);
  return offset_pointer(front, 1);
}

static void sdcg_free(void *p) {
  int index = -1;

  if (p == 0) return;

  if (p < sbrk(0) || sdcg_heap == NULL) {
    //fprintf(stderr, "calling libc free %p\n", p);
    free(p);
    return;
  }

  pthread_mutex_lock(&sdcg_heap->mutex);

  sdcg_mm_t *front = (sdcg_mm_t*)offset_pointer(p, 0);
  
  if (front->size <= 2048) {
    if ((byte*)front < sdcg_heap->base || (byte*)front >= sdcg_heap->end) {
      pthread_mutex_unlock(&sdcg_heap->mutex);
      free(p);
      //V8_Fatal(__FILE__,__LINE__,"invalid address %p", p);
      return;
    }

    switch (front->size) {
    case 16:   index = 0; break;
    case 32:   index = 1; break;
    case 64:   index = 2; break;
    case 128:  index = 3; break;
    case 256:  index = 4; break;
    case 512:  index = 5; break;
    case 1024: index = 6; break;
    case 2048: index = 7; break;
    default:
      V8_Fatal(__FILE__, __LINE__, "invalid size %d\n", front->size);
    }
  } else {
    index = 8;
  }

  front->next = sdcg_heap->freelist[index];
  sdcg_heap->freelist[index] = front; 

  pthread_mutex_unlock(&sdcg_heap->mutex);
}
#endif

void* Malloced::New(size_t size) {
#ifdef SEC_DYN_CODE_GEN
  if (sdcg_shared_vm_start == NULL)
    sdcg_shared_vm_init();

  void* result = sdcg_malloc(size);
#else
  void* result = malloc(size);
#endif
  if (result == NULL) {
    v8::internal::FatalProcessOutOfMemory("Malloced operator new");
  }
  return result;
}


void Malloced::Delete(void* p) {
#ifdef SEC_DYN_CODE_GEN
  sdcg_free(p);
#else
  free(p);
#endif
}


void Malloced::FatalProcessOutOfMemory() {
  v8::internal::FatalProcessOutOfMemory("Out of memory");
}


#ifdef DEBUG

static void* invalid = static_cast<void*>(NULL);

void* Embedded::operator new(size_t size) {
  UNREACHABLE();
  return invalid;
}


void Embedded::operator delete(void* p) {
  UNREACHABLE();
}


void* AllStatic::operator new(size_t size) {
  UNREACHABLE();
  return invalid;
}


void AllStatic::operator delete(void* p) {
  UNREACHABLE();
}

#endif


char* StrDup(const char* str) {
  int length = StrLength(str);
  char* result = NewArray<char>(length + 1);
  OS::MemCopy(result, str, length);
  result[length] = '\0';
  return result;
}


char* StrNDup(const char* str, int n) {
  int length = StrLength(str);
  if (n < length) length = n;
  char* result = NewArray<char>(length + 1);
  OS::MemCopy(result, str, length);
  result[length] = '\0';
  return result;
}


void PreallocatedStorage::LinkTo(PreallocatedStorage* other) {
  next_ = other->next_;
  other->next_->previous_ = this;
  previous_ = other;
  other->next_ = this;
}


void PreallocatedStorage::Unlink() {
  next_->previous_ = previous_;
  previous_->next_ = next_;
}


PreallocatedStorage::PreallocatedStorage(size_t size)
  : size_(size) {
  previous_ = next_ = this;
}

} }  // namespace v8::internal
