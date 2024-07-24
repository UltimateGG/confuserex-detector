## ConfuserEX Yara Rules

Rules for detecting ConfuserEx and its options. Quickly made and dirty.

This can help in detecting malware, and just reverse engineering so you can easily see what protections to deobfuscate.

#### Supported Protections

- Watermark
- General (Watermark removed/unicode renamed)
- Anti Ildasm
- Anti Tamper (Normal & JIT distinct rules)
- Constants encryption
- Control Flow
- Anti Dump
- Anti Debug (safe, win32, antinet distinct rules)
- Invalid Metadata
- Reference Proxy (Strong only)
- Resource protection
- Packer/Compressor

## !! Note !!

Some protections may hide others. For example, if Anti-tamper is on, it may hide control flow. When you deobfuscate/remove a layer you can run the rules again to see what protections are left.

### TODO:

- Detect NEO ConfuserEx, ConfuserEx 2
- Better rules so that they don't hide each other
