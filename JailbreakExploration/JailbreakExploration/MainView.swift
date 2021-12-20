//
//  ContentView.swift
//  JailbreakExploration
//
//  Created by Beckett O'Brien on 12/19/21.
//

import SwiftUI

struct MainView: View {
    var body: some View {
        Button(action: {
            jailbreak()
        }) {
            Text("Jailbreak")
                .padding(.horizontal)
                .padding()
                .background(Color.blue)
                .foregroundColor(.white)
                .font(.headline)
                .cornerRadius(12.5)
        }
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        MainView()
    }
}
