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
![Dissassembly of task_terminate in Hopper](/assets/hopper-dissassembly-task-terminate)
As you can see in the source code, it checks if the task is null, then checks if the `bsd_info`  of that task is null. In the dissassembly, you can see that `x0` is copied into `x20` before jumping if `x0` is zero, then the contents of `x20` + the offset `0x390` are copied into `x8`, which is then compared against zero. Clearly, `x0`/`x20` is the task struct, and `[x20 + #0x390]` is the pointer to bsd_info and the proc struct. If we replace our offset of `0x3A0` with `0x390` in our exploit code and run it, we see `getuid() returns 0` is logged. Hooray! Now that we know our exploit works, we can move on to the rest of the jailbreak.

# Part 2: I'm not sure what comes next
I know that before I can consider this a working jailbreak, I need to accomplish a few things:
 - Disable codesigning
 - Remount `/` as r/w
 - Provide a daemon to give other processes root
 - Bootstrap useful binaries
I might add tweak injection, but for now my goal is going to be an ssh shell.
