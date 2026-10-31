# ADR 0009: Inbound SMTP on James Protocol Handlers

Status: accepted for Phase 4 (minimal policy; [mail policy](../components/mail-policy.md) is step 11).

## Context

[PLAN step 10](../../PLAN.md) and the [inbound SMTP component](../components/smtp-inbound.md) need a port-25 receiver with the following properties:

- It never unlocks a mailbox.
- It never relays.
- It keeps no plaintext spool.
- It answers `250` only after durable blob and receipt commits.

[ADR 0005](0005-james-integration.md) already chose `protocols-smtp` plus `protocols-netty` over `james-server-protocols-smtp`, which brings the mailet container, mail queue, and server distribution.

## Spike findings (James 3.9.1 sources)

- **No temp files:** `protocols-smtp` and `protocols-netty` contain no `createTempFile`, `DeferredFileOutputStream`, or `java.io.tmpdir` use.
- **Unbounded DATA buffer:** `MailEnvelopeImpl` buffers DATA in an unbounded in-memory `UnsynchronizedByteArrayOutputStream`. On its own it imposes no size limit.
- **`MailSizeEsmtpExtension` is unsuitable:**
  - It parses `SIZE` as an `int`, so a valid large value becomes a syntax error.
  - It logs envelope addresses.
  - When the limit is hit, it still forwards the DATA terminator down the chain, so whether the message hooks run depends on handler order.
- **`ReceivedHeaderGenerator`** does a blocking reverse-DNS lookup (`getHostName()`) per message and names the recipient when there is only one.
- **STARTTLS injection:** `NettyServer.Factory` defaults to a plain line framer with no STARTTLS command-injection detection. `AllButStartTlsLineChannelHandlerFactory` provides that detection.
- **Overlong lines:** Netty's line decoder drops an overlong line and James keeps the session going. Inside DATA that silently truncates the message, which could still end in `250`.
- **Threading:** `NettyServer` runs protocol handlers on a separate 16-thread `DefaultEventLoopGroup`, not the I/O event loop. Blocking delivery (fsync) in a message hook is therefore bounded and does not stall the I/O threads.

## Decision

`shem-smtp` composes James's command handlers with Shem-owned hooks and filters:

- **Handler list:** an explicit list containing EHLO/HELO, MAIL, RCPT, DATA, RSET, NOOP, QUIT, STARTTLS, and unknown-command.
  - Not included: AUTH, VRFY, EXPN, HELP, and the default handler set.
  - Relaying is never allowed, AUTH is never announced, and HELO/EHLO syntax and address brackets are enforced.
- **Recipients (`RecipientPolicy`):**
  - A recipient in a non-local domain gets `550 5.7.1`.
  - Unknown, disabled, and deleted recipients all get the identical response `550 5.1.1`.
  - After `smtp.maxUnknownRecipients` such rejections, the connection is closed with `421`.
  - Exceeding `smtp.maxRecipients` gets `452 4.5.3`.
  - The hook never returns DECLINED, so James's default acceptance cannot apply.
- **Anti-enumeration choice:** recipients are rejected at RCPT time rather than accepted and discarded or bounced later, which would mean backscatter or silent loss. The residual probe surface is bounded by the per-connection limit and connection-count limits.
- **Size (`SizeLimit`):**
  - A declared `SIZE` is parsed as a `long`.
  - The DATA stream is counted line by line. Once it is over the limit, lines are dropped without buffering, the envelope is wiped, and the reply is `552 5.3.4`. The message hooks never run.
- **Buffering (`SpoolingEnvelope`):**
  - Message data is held in memory up to a threshold (1 MiB in `serve`). Beyond that it goes to an `EncryptedSpool`, which is streaming AEAD under a key held only in that object.
  - The envelope is wiped on completion, rejection, disconnect, or overlong line.
  - The spool directory (`spool/inbound`) is swept at start. Its files are unreadable after a crash and none was ever acknowledged.
- **Overlong lines:** they end the session (`500 5.5.2`), and the transaction is discarded.
- **Trace headers:** `Return-Path` and `Received` are added without reverse DNS and without naming recipients. They exist only inside the encrypted message.
- **Delivery (`DeliveryHook`):**
  - One `DeliveryRequest` per transaction with a fresh internal transaction id and one recipient per distinct mailbox, so aliases and duplicate RCPTs deliver once.
  - The target is INBOX with no flags. Policy tags arrive in step 11.
  - The reply is `250 2.6.0` only when every mailbox reports a durable blob and receipt.
  - Any temporary failure (storage, I/O, disk full, unexpected exception) gets `451 4.3.0`, and quota gets `452 4.2.2`. The only permanent outcome, size, gets `552 5.3.4`.

## Consequences and residual risk

- **Duplicates:** SMTP has one DATA reply for all recipients. If one mailbox fails temporarily after another committed, the client's retry duplicates the message in the committed mailbox. The same is true of a disconnect after commit but before the client reads `250`. Shem does not deduplicate by Message-ID or body hash.
- **No DSNs yet:** permanent per-recipient failures cannot produce a DSN until outbound delivery exists (step 13). Today the only permanent delivery failure (size) applies to all recipients alike.
- **Connection limits:** James counts concurrent connections per exact IP; there is no IPv6 /64 grouping yet. There is no PROXY protocol support and no rate limit beyond connection counts and the unknown-recipient limit.
- **James's own responses** echo the client's addresses back to the client (for example, `Recipient <...> OK`). The address is never logged; James's logging goes to `slf4j-nop`.
- **Upgrades:** every James upgrade must repeat this inventory: temp files, envelope buffering, framer defaults, and which hooks run on rejection.

## Evidence

- `InboundSmtpIT`, black-box tests over a real socket:
  - **Delivery:** delivery to a locked mailbox is readable after unlock, with dot-unstuffing, trace headers, no recipient in `Received`, and no plaintext markers on disk.
  - **Relay:** relay attempts are refused, before and after STARTTLS.
  - **Recipient probing:** unknown recipients all get the identical response, and repeated probing disconnects.
  - **Duplicates:** alias and duplicate recipients deliver once.
  - **Recipient limit:** returns `452`.
  - **Size:** declared and actual oversize are both rejected without delivery, and the connection remains usable afterwards.
  - **Spooling:** a large message spools only ciphertext and creates no `java.io.tmpdir` files.
  - **Disconnect:** a disconnect mid-DATA delivers nothing and wipes the spool.
  - **Disk full:** a simulated disk-full blob write gets `451`, and the next transaction succeeds.
  - **STARTTLS injection:** refused.
  - **Overlong lines:** close the connection without delivery.
  - **Pipelining:** replies come back in order.
- `EncryptedSpoolTest`: streaming round trip with ciphertext only on disk, and the size limit.
- **Manual check** of the packaged jar (`serve` with `smtp.bind`), using `openssl s_client -starttls smtp`: delivery accepted and relay refused.
- **Not yet covered:** kill -9 around durability barriers (only in-process fault injection), interoperability with real MTAs, James's own protocol test suite.
