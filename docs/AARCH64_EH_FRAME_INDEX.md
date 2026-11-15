# AArch64 ELF unwind-entry index

This offline tool parses the supported GNU .eh_frame_hdr encoding used by an
AArch64 ELF and resolves a requested address only when it exactly matches an
FDE initial-PC entry.

Supported header encodings are version 1, pcrel/sdata4 for the .eh_frame
pointer, udata4 for the FDE count, and datarel/sdata4 for the binary-search
table. The parser validates the table bounds, strict PC ordering, unique FDE
pointers, executable-section membership, .eh_frame membership, and zero-only
trailing padding.

For a resolved entry, the reported byte window ends at the next FDE start in
the same executable section, or at the section boundary for the final entry.
This is a conservative analysis window, not the exact FDE function length,
not a control-flow graph, and not proof that a call executes.

The CLI accepts private target addresses but emits only aggregate counts and
window sizes. It never prints addresses, raw instructions, ELF bytes, APK
bytes, endpoint values, or packet data. CI uses fabricated ELF-header fixtures
only; it never receives or downloads the original APK.

This tool is intended to bound native helper call targets that are not
metadata-backed managed method entries. It does not identify a helper's
semantic name by itself.
