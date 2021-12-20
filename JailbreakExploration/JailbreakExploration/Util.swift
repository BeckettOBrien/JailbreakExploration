//
//  Util.swift
//  JailbreakExploration
//
//  Created by Beckett O'Brien on 12/19/21.
//

import Foundation

func log(_ items: Any..., seperator: String = " ", terminator: String = "\n") {
    print((items as! [String]).joined(separator: seperator), separator: seperator, terminator: terminator);
    // Eventually I might add an on-screen log output
}
