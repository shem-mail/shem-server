# ADR 0007: Process Roles and IPC

Status: open.

Modules are split so the boundary can be enforced later: `shem-delivery` depends only on identity (public keys) and stores, never on `shem-mailbox` (sessions/private keys). Until this ADR is decided, all roles run in one JVM under one service user, which does **not** yet satisfy runtime.md's requirement that a compromised inbound role cannot reach unlocked keys. Options to evaluate when inbound SMTP exists: (a) separate inbound process with public-key-only file permissions writing blobs/receipts directly, notifying the authenticated role over a protected Unix socket that carries no plaintext; (b) single process (rejected unless the threat model is amended). Option (a) needs no plaintext IPC for inbound, because delivery output is already ciphertext.
