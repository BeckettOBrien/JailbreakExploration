//
//  KernRW.hpp
//  JailbreakExploration
//
//  Created by Beckett O'Brien on 12/21/21.
//

#ifndef KernRW_hpp
#define KernRW_hpp
#import <Foundation/Foundation.h>


bool KernRW_init(uint64_t proc);
void KernRW_deinit(void);

uint32_t kread32(uint64_t addr);
uint64_t kread64(uint64_t addr);
uint64_t kreadptr(uint64_t addr);
void kread(uint64_t addr, void *data, size_t count);
void kwrite64(uint64_t addr, uint64_t val);
void kwrite32(uint64_t addr, uint32_t val);
void kwrite(uint64_t addr, void *data, size_t count);

#endif /* KernRW_hpp */
