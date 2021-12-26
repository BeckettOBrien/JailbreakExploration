//
//  Offsets.swift
//  JailbreakExploration
//
//  Created by Beckett O'Brien on 12/20/21.
//

import Foundation

struct Offsets {
    struct TASK {
        #if __arm64e__
        static let BSD_INFO: UInt64 = 0x3A0;
        #else
        static let BSD_INFO: UInt64 = 0x390;
        #endif
    }
    struct PROC {
        static let UCRED: UInt64 = 0xF0;
    }
    struct UCRED {
        static let CR_UID: UInt64 = 0x18;
        static let CR_RUID: UInt64 = 0x1C;
        static let CR_SVUID: UInt64 = 0x20;
        static let CR_LABEL: UInt64 = 0x78;
    }
    struct LABEL {
        static let SANDBOX: UInt64 = 0x10;
    }
}
