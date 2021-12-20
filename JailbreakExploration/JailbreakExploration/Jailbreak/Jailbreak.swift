//
//  Jailbreak.swift
//  JailbreakExploration
//
//  Created by Beckett O'Brien on 12/19/21.
//

import Foundation

func jailbreak() {
    log("[+] Starting Jailbreak...");
    // Register for logs from the exploit
    NotificationCenter.default.addObserver(forName: Notification.Name("cicuta_log"), object: nil, queue: nil, using: {
        log($0.object ?? "[!] No log?");
    });
    cicuta_virosa();
}
