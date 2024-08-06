## ConfuserEX Yara Rules

Tool for reverse engineering ConfuserEx config.

This can help in detecting malware, and just reverse engineering so you can easily see what protections to deobfuscate.

#### Supported Protections

- Watermark <small>(ConfuserEx_Watermark)</small>
- General <small>(ConfuserEx_General)</small>
  - Detects ConfuserEx even when watermarks are removed using a renaming pattern it uses internally
- Anti Ildasm <small>(SuppressIldasm)</small>
- Anti Tamper <small>(ConfuserEx_AntiTamper_Normal, ConfuserEx_AntiTamper_JIT, ConfuserEx_2_AntiTamper_Anti, ConfuserEx_2_AntiTamper_Normal)</small>
  - Distinct rules for normal (1 and 2), JIT mode, or Anti mode (ConfuserEx 2)
- Constants encryption <small>(ConfuserEx_Constants)</small>
- Control Flow <small>(ConfuserEx_ControlFlow_Switch)</small>
  - Switch mode only
- Anti Dump <small>(ConfuserEx_AntiDump)</small>
- Anti Debug <small>(ConfuserEx_AntiDebug_Safe, ConfuserEx_AntiDebug_Win32, ConfuserEx_AntiDebug_Antinet)</small>
  - Distinct rules for safe, win32, and antinet
- Invalid Metadata <small>(ConfuserEx_InvalidMetadata)</small>
- Reference Proxy
  - Strong mode only <small>(ConfuserEx_RefProxy_Strong)</small>
- Resource protection <small>(ConfuserEx_Resources_Protection)</small>
- Packer/Compressor <small>(ConfuserEx_Packer)</small>

Not every single config option is detected (e.g. constants.decoderCount), but the major, useful to know ones are.

## !! Note !!

If Anti-tamper is on, the following rules will not be detected:

- Constants encryption
- Control Flow

This is due to anti tamper dynamically encrypting the code so the bytes are different each time. Simply remove the anti-tamper and then run the rules again.

### TODO:

Detect specific alterations for:

- Original: https://github.com/yck1509/ConfuserEx (Done)
- ConfuserEx Fork: https://github.com/mkaring/ConfuserEx
- ConfuserEx 2: https://github.com/Desolath/ConfuserEx2/commits/master/
- NEO ConfuserEx: https://github.com/XenocodeRCE/neo-ConfuserEx
