# Evidence ledger and transport boundary

The evidence ledger is public metadata only. It tracks the provenance and
review status of offline observations; it does not contain an AOW packet
schema and does not prove APK compatibility.

References are restricted to short repository-local locators such as
`issue:2`, `docs/PROTOCOL.md#framing`, and
`metadata/type:123`. The validator rejects URI schemes, DNS hostnames,
IPv4/IPv6 literals, localhost, host:port values, and secret-like identifiers.
Path-and-line references remain allowed. This is a conservative metadata
filter, not a general-purpose data-loss-prevention system.

Never put APK bytes, extracted proprietary assets, raw packet/capture bytes,
private capture paths, endpoint values, account data, or credentials in this
public ledger. Keep original artifacts and detailed native analysis in the
authorized private workspace.

`protocol_ready()` is an evidence bookkeeping gate only. It requires all
required topics to have authorized end-to-end evidence for one APK fingerprint;
offline static analysis and synthetic fixtures cannot satisfy that gate.
