# Keep UniFFI/JNA bindings when the production Rust bridge is packaged.
-keep class uniffi.wallet_core.** { *; }
-keep class com.sun.jna.** { *; }
