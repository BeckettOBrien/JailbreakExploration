# Part 1: Setting things up
I'm gonna start by setting up an Xcode project with a simple button that starts the jailbreak. I'm going to use the cicuta_virosa exploit because I'm working on iOS 14, so I'm also importing the files I need for that. The exploit comes with a demo to get root, so I'm just going to work on making sure that works for now, but eventually I'll do it myself. Unfortunately, I'm testing on an iPhone X and cicuta_virosa comes with offsets hardcoded for A12-A14, specifically the pointer to the process structure from the task structure, otherwise known as `bsd_info` is different:
```c
uint64_t proc_pac = read_64(task + 0x3A0); // For arm64e
```
If we try to run the exploit now on an arm64 device, it will kernel panic before we even overwrite the credentials. From some previous reading I've done, I know that to find offsets you can either calculate them by hand using the publicly available XNU definitions or find a function in the kernelcache that accesses the property you're looking for. I've heard that using the public XNU source isn't very reliable because there are a lot of differences between it and the version used in iOS. Additionally, it looks like it would take a lot of work to work through all the definitions and ifdefs, especially without having much experience with all the internals of iOS already. In order to find a reference to bsd_info in the kernelcache, you have to decompress it and hopefully find some symbols. You can use [jtool2](http://www.newosxbook.com/tools/jtool.html) to do both, just unzip the IPSW for the device and version you're looking for and run `jtool2 -dec /path/to/kernelcache`. The decompressed kernelcache should end up at `/tmp/kernel`, and you can get a list of symbols by running `jtool2 --analyze /path/to/decompressed/kernel` (jtool2 can run analysis on compressed kernelcaches, but you need to decompress it anyway before viewing it in something like hopper, ghidra, or IDA). You can have jtool symbolicate the kernelcache using the companion file using `jtool2 --symbolicate /path/to/kernelcache`, or you can just go through the companion file manually and go to the address for each function you want to look at (jtool wouldn't use my companion file for whatever reason, so I had to do it manually). Next, you can open up the decompressed kernelcache in a decompiler like Hopper, IDA, or Ghidra (I used Hopper because it's fairly intuitive. The free version is missing a lot of features and it will close every 30 minutes, but it's perfectly useable for this). After a while of searching, I found the method `task_terminate`, with a reference to bsd_info, a symbol in the kernelcache, and public source code:
```c
task_terminate(task_t task) {
    if (task == TASK_NULL) {
        return KERN_INVALID_ARGUMENT;
    }

    if (task->bsd_info) {
        return KERN_FAILURE;
    }

    return task_terminate_internal(task);
}
```
Symbol: `0xfffffff007ac9398|__Xtask_terminate|`  
Hopper dissassembly:
![Dissassembly of task_terminate in Hopper](/assets/hopper-dissassembly-task-terminate.png)
As you can see in the source code, it checks if the task is null, then checks if the `bsd_info`  of that task is null. In the dissassembly, you can see that `x0` is copied into `x20` before jumping if `x0` is zero, then the contents of `x20` + the offset `0x390` are copied into `x8`, which is then compared against zero. Clearly, `x0`/`x20` is the task struct, and `[x20 + #0x390]` is the pointer to bsd_info and the proc struct. If we replace our offset of `0x3A0` with `0x390` in our exploit code and run it, we see `getuid() returns 0` is logged. Hooray! Now that we know our exploit works, we can move on to the rest of the jailbreak.

# Part 2: Re-implement privelege escalation and read/write primitive
Before we do anything else, I want to re-implement the privelege escalation part of the exploit in swift so that the exploit is only responsible for building the read/write primitive. Based on my current understanding of the exploit (and jailbreaking in general), cicuta_virosa's read and write methods have to spray allocate a lot of objects before being able to read or write to a specific address in kernel memory. I'm not sure if it's a good idea to get an actual task port for the kernel so we can use the official methods for modifying the memory of another process (we might have to do this regardless for the daemon, but I'm not sure). I know that `task_for_pid(0)` isn't allowed even with the entitlement, and we can't patch it directly because of KPP and KTRR, but I'm wondering if it's worthwhile to find a different method of getting tfp0. After trying to overwrite the credentials in swift using cicuta_virosa's `write_20` method, it seems like I *am* going to need to build a more robust method of reading and writing kernel memory, because we can only write 20 bits at a time and we can't write just a value, we have to give it the address of a pointer with the data we want to write. Looking at Taurine's [KernelRW](https://github.com/Odyssey-Team/Taurine/blob/0ee53dde05da8ce5a9b7192e4164ffdae7397f94/Taurine/exploit/common/KernelRW.cpp), it seems like one possible strategy is to use IOSurfaces to read and write to kernel memory. I think I can figure out how to actually read and write from an IOSurface, but I still don't understand how I can get the IOSurface to overlap kernel memory (which is how I assume this works). As far as I can tell, this is the code segment responsible for actually setting up the IOSurface to write to kernel memory:
```c
{
    uint8_t buf[20];
    for (int i=0; i<sizeof(buf); i+=8) {
        *((uint64_t*)&buf[i]) = kread64(p.where-20+8+4+i);
    }
    *((uint64_t*)&buf[20-8-4]) = p.what;
    write_20(p.where-20+8+4,buf);
}
```
I'm not entirely sure that it is, but it seems to be the only part of setting up the IOSurface that involves writing to kernel memory with the exploit's utilities, and (while I don't know for sure) I doubt you can create an IOSurface that can write to kernel memory by only reading from kernel memory. Unfortunately, this code segment (and the rest of Taurine's kernel read/write method) is really confusing, but I guess that's why I'm doing this in the first place. Rather than try to set up everything that Tuarine uses and not learn anything, I'm gonna just implement the simple IOSurface read/write methods and just add things as I figure out I need them. I've read through [pattern-f's presentation](https://i.blackhat.com/USA21/Wednesday-Handouts/us-21-Everything-Has-Changed-In-IOS-14-But-Jailbreak-Is-Eternal.pdf) on this technique and looked through their iOS 14 [pre-jailbreak](https://github.com/pattern-f/TQ-pre-jailbreak), but I have to admit that I'm still very confused. In addition to not having much experience with specific iOS internals like IOKit, both pattern-f's and Taurine's implementation are in C++, which I have been avoiding learning for quite a while. I tried implementing it in swift but I quickly abandoned that due to needing C structs and the way pointers work in swift (there is so much type safety in swift that what C can accomplish with the `&` operator takes an unnecessary amount of time in swift), so I guess I need to get past my difference with C++ after all (nope, it works just fine with objective-c). After reading through the slides a little more, it looks like the snippit above actually sets up a pipe that can control some of the properties we need on the IOSurface. Update: I (think) I set up the IOSurface by reading through what pattern-f does in [IOSurface-lib.c](https://github.com/pattern-f/TQ-pre-jailbreak/blob/main/mylib/IOSurface_lib.c) and I think I have a decent understanding of how the read/write primitives work, mostly. First, we create a pipe and a buffer that we repeatedly write into the pipe (excluding the last byte for some reason) until it is full, then we read it out once into the buffer (again excluding the last byte for some reason). Next I think we find the location of the pipe buffer in the kernel and replace the address of the IOSurfaceRootUserClient's surfaceClients with it. Now we can make a struct for a fake surfaceClient and use it to overwrite the values that influence the read and write locations and values of `iosurface_s_get_ycbcrmatrix` (read) and `iosurface_s_set_indexed_timestamp` (write) by writing our fake client to the pipe. As far as I can tell, spraying the pipe is necessary so that the pipe is always one read away from full, but I'm not sure (I don't actully think spraying the pipe is necessary because it only writes once to each pipe, and there is only one pipe for some reason). Also, I'm a little confused as to why we can't just use the pipe to write to kernel memory at this point (Update: I think it's probably because pipe buffers have some sort of zone safety and the IOSurface happens to be in that zone or something). I got a working implementation of the kernel read and write functions and used it to get root successfullly. For some reason, I have to run `setuid(0)` twice for it to actually work, which is weird. I'm also gonna take this opportunity to implement a sandbox escape, which should be as simple as nulling out the sandbox slot of the MAC label in the ucred (Although Taurine saves the sandbox slot, nulls it out, runs `setuid(0)`, and then restores it, so I'm not sure if this will work. We'll see though!). It appears that simply nulling out the sandbox slot doesn't work and Taurine's method does, but I think that is because I'm nulling `cr_svuid` and calling `setuid(0)` rather than overwriting all of the credentials. I still don't really know why I need to run `setuid(0)` twice and why I need to have the sandbox slot nulled when running `setuid(0)` but I can restore it after. My assumption is that the credentials are being cached somewhere and setuid updates them, but overwriting all the creds and the snadbox slot manually and not running setuid at all works perfectly and even escapes the sandbox. So there we go, we got root *and* escaped the sandbox! Two more things I want to do before I continue are: pattern-f has a method of making the exploit faster implemented in his pre-jailbreak, and shutting down the jailbreak app (even after restoring a uid and gid of 501) causes a kernel panic.
## Part 2.5: Speeding up the exploit and stopping kernel panics
First I'm going to speed up the exploit because that will make testing everything else a lot faster. It's mostly related to vouchers and stuff I don't think I'll fully understand for a while, so I doubt I'll be able to come up with my own implementation, but I will try to walk through it and figure out how it works. The time consuming part of the exploit is mostly contained in this block of code:
```c
ipc_voucher_t redeemed_voucher = IPC_VOUCHER_NULL;
for (uint32_t i = 1; i < 167777280; ++i)
{
    assert(redeem_voucher(uafed_voucher, &redeemed_voucher) == KERN_SUCCESS);
}
```
The `redeem_voucher` function is:
```c
kern_return_t redeem_voucher(ipc_voucher_t target, ipc_voucher_t* result)
{
    mach_voucher_attr_recipe_data_t recipe = {
        .key = MACH_VOUCHER_ATTR_KEY_USER_DATA,
        .command = MACH_VOUCHER_ATTR_REDEEM,
        .previous_voucher = target
    };

    return create_voucher(&recipe, result);
}
```
Pattern-f introduces a new function named `redeem_voucher_fast` that takes in a voucher and a reference count:
```c
static void redeem_voucher_fast(ipc_voucher_t voucher, uint32_t refs)
{
    mach_voucher_attr_recipe_data_t *recipes = malloc(sizeof(recipes[0]) * refs);
    for (int i = 0; i < refs; i++) {
        recipes[i].key = MACH_VOUCHER_ATTR_KEY_USER_DATA;
        recipes[i].command = MACH_VOUCHER_ATTR_REDEEM;
        recipes[i].previous_voucher = voucher;
        recipes[i].content_size = 0;
    }
    ipc_voucher_t redeemed_voucher = IPC_VOUCHER_NULL;
    kern_return_t kr;
    kr = host_create_mach_voucher(mach_host_self(), (mach_voucher_attr_raw_recipe_array_t)recipes, sizeof(recipes[0]) * refs, &redeemed_voucher);
    assert(kr == KERN_SUCCESS);
    free(recipes);
}
 ```
The function allocates an array of recipes for mach vouchers and creates one for each reference. The recipes created in the fast function are nearly identical to the ones created in the original function, the one exception being that `content_size` is set to 0, so I wonder if it's even necessary to set that. The redeem part of the main exploit has been replaced with:
```c
uint32_t redeem_count = 0xa001400 - 1;
uint32_t once = MACH_VOUCHER_ATTR_MAX_RAW_RECIPE_ARRAY_SIZE / sizeof(mach_voucher_attr_recipe_data_t);
uint32_t times = redeem_count / once;
for (int i = 0; i < times; i++) {
    redeem_voucher_fast(uafed_voucher, once);
}
if (redeem_count % once) {
     redeem_voucher_fast(uafed_voucher, redeem_count % once);
}
```
The redeem count is equal to the number of loops in the old implementation (I still don't know what determined the redeem count but I might look into the exploit in more detail later to hopefully get some understanding) and the once variable seems to be the maximum number of vouchers we can make with one call to `redeem_voucher_fast`. If that's the case, then times is the number of loops we need to achieve the same number of redeems as the original code (I think a redeem just increases the reference count of a voucher). After implementing this new method, everything goes a lot faster, and we know that setting the content size is necessary (I'm still not entirely sure why, but I assume the max number of recipes is assuming a content size of 0). Now I want to look into stopping the kernel panic that happens every time the app quits. After a little testing, I've determined that it happens in `KernRW_deinit`. I assume it's because the pipe is being closed when the IOSurfaceRootUserClient occupies the buffer (I also found out that I was wrong earlier, we modify the IOSurfaceRootUserClient to point to the pipe buffer, not move the pipe buffer to overlap the userclient). After restoring the userclients pointer, the device no longer panics on `KernRW_deinit`, but it does still panic when the app is quit, with the message:
> kfree: addr 0xffffffe4ccaa5dd4, size 368 found in heap kext.* instead of default.*

I assume there must be something left over from cicuta_virosa's r/w primitives that isn't in the right place when it gets freed, but unfortunately I don't understand the exploit well enough to fix that. I might look into it again later but for now I don't think it's worth the time and I really want to move on. I'm also not going to clean up the KernRW stuff because we don't really need it and it won't even work without the original r/w methods so it kind of defeats the purpose. I'll come back to it later if I need to.
