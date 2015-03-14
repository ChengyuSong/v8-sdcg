// Copyright 2014 the Chengyu Song. All rights reserved.
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

#ifndef V8_SDCG_H_
#define V8_SDCG_H_

#ifdef SEC_DYN_CODE_GEN
extern "C" int sdcg_mode __attribute__((visibility ("default")));
#endif

namespace v8 {
namespace internal {

#ifdef SEC_DYN_CODE_GEN
extern uint8_t* sdcg_shared_vm_start;
extern uint8_t* sdcg_shared_vm_end;
extern uint8_t* sdcg_scratch_page;
extern volatile uint8_t* sdcg_stack_base;
extern void sdcg_shared_vm_init();
extern void* sdcg_reserve(size_t size);
extern void* sdcg_mmap(void* base, size_t size, int prot);
extern void* sdcg_unmap(void* base, size_t size);
extern void sdcg_enable_sandbox();

enum SDCG_IC_CALL {
  CALL_MISS,
  LOAD_MISS
};

enum SDCG_FIELD_SIZE {
  BYTE,
  INT,
  UINT32,
  OBJECT
};

class CompilationInfo;

extern bool sdcg_make_code(CompilationInfo* info, bool crankshaft = false);
extern void sdcg_copy_bytes(uint8_t* dest, uint8_t* src, size_t size);
extern void sdcg_write_field(Code* code, int offset, void* value, int size); 
extern void sdcg_write_field(Code* code, int offset, unsigned long value, int size); 
extern void sdcg_set_target_address_at(Address pc, Code* code);
extern Handle<Code> sdcg_new_code(Isolate* isolate, CodeDesc* desc, uint32_t flags, 
                                 Handle<Object> self_ref,
                                 bool immovable = false, bool crankshaft = false);
#endif

} }  // namespace v8::internal

#endif  // V8_SDCG_H_
