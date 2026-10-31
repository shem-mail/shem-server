package org.shem.identity;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.shem.common.FormatException;
import org.shem.common.IdGenerator;
import org.shem.common.OpaqueId;
import org.shem.crypto.MailboxPublicKey;

class IdentityServiceTest {
  private static final SecureRandom RANDOM = new SecureRandom();
  @TempDir Path dir;
  private MutableClock clock;
  private IdentityService identity;

  @BeforeEach
  void setUp() throws Exception {
    clock = new MutableClock(Instant.parse("2026-10-25T10:00:00Z"));
    identity = open();
  }

  private IdentityService open() throws Exception {
    return IdentityService.open(
        dir.resolve("routing/directory.bin"),
        clock,
        IdGenerator.secure(RANDOM),
        DeliveryPolicy.DEFAULT,
        Duration.ofDays(30));
  }

  private static MailboxPublicKey key(int version) {
    byte[] bytes = new byte[32];
    RANDOM.nextBytes(bytes);
    return new MailboxPublicKey(version, bytes);
  }

  private Account account(String address) throws Exception {
    return identity.createAccount(
        OpaqueId.random(RANDOM), EmailAddress.parse(address), key(1), 0, Duration.ofDays(1));
  }

  @Test
  void routesRecipientsWithoutAnyPrivateState() throws Exception {
    identity.createDomain("Example.ORG");
    Account alice = account("Alice@example.org");
    List<RecipientRoute> routes =
        identity.resolveRecipient(EmailAddress.parse("alice@EXAMPLE.org"));
    assertThat(routes)
        .singleElement()
        .satisfies(
            r -> {
              assertThat(r.mailboxId()).isEqualTo(alice.mailboxId());
              assertThat(r.publicKey()).isEqualTo(alice.publicKey());
            });
    assertThat(identity.resolveRecipient(EmailAddress.parse("bob@example.org"))).isEmpty();
  }

  @Test
  void persistsAndReloadsDirectory() throws Exception {
    identity.createDomain("example.org");
    Account alice = account("alice@example.org");
    identity.createAlias(
        EmailAddress.parse("info@example.org"),
        List.of(alice.address()),
        List.of(alice.mailboxId()));
    IdentityService reopened = open();
    assertThat(reopened.directory().generation()).isEqualTo(identity.directory().generation());
    assertThat(reopened.account(alice.mailboxId())).contains(alice);
    assertThat(reopened.resolveRecipient(EmailAddress.parse("info@example.org"))).hasSize(1);
  }

  @Test
  void corruptDirectoryFailsClosed() throws Exception {
    identity.createDomain("example.org");
    Path file = dir.resolve("routing/directory.bin");
    byte[] data = Files.readAllBytes(file);
    Files.write(file, java.util.Arrays.copyOf(data, data.length - 3));
    assertThatThrownBy(this::open).isInstanceOf(FormatException.class);
  }

  @Test
  void rejectsAliasCyclesAndExternalTargets() throws Exception {
    identity.createDomain("example.org");
    Alias a =
        identity.createAlias(
            EmailAddress.parse("a@example.org"),
            List.of(EmailAddress.parse("b@example.org")),
            List.of());
    identity.createAlias(
        EmailAddress.parse("b@example.org"),
        List.of(EmailAddress.parse("c@example.org")),
        List.of());
    assertThatThrownBy(
            () ->
                identity.updateAlias(
                    a.aliasId(),
                    a.version(),
                    List.of(EmailAddress.parse("a@example.org")),
                    List.of()))
        .isInstanceOf(IdentityException.class)
        .extracting(e -> ((IdentityException) e).reason())
        .isEqualTo(IdentityException.Reason.ALIAS_CYCLE);
    assertThatThrownBy(
            () ->
                identity.createAlias(
                    EmailAddress.parse("fwd@example.org"),
                    List.of(EmailAddress.parse("someone@elsewhere.net")),
                    List.of()))
        .isInstanceOf(IdentityException.class);
  }

  @Test
  void senderIdentityRequiresOwnershipOrAliasGrant() throws Exception {
    identity.createDomain("example.org");
    identity.createDomain("other.net");
    Account alice = account("alice@example.org");
    Account bob = account("bob@other.net");
    identity.createAlias(
        EmailAddress.parse("sales@example.org"),
        List.of(alice.address()),
        List.of(alice.mailboxId()));
    assertThat(identity.mayUseSenderIdentity(alice.mailboxId(), alice.address())).isTrue();
    assertThat(
            identity.mayUseSenderIdentity(
                alice.mailboxId(), EmailAddress.parse("sales@example.org")))
        .isTrue();
    assertThat(identity.mayUseSenderIdentity(bob.mailboxId(), alice.address())).isFalse();
    assertThat(
            identity.mayUseSenderIdentity(bob.mailboxId(), EmailAddress.parse("sales@example.org")))
        .isFalse();
    assertThat(
            identity.mayUseSenderIdentity(alice.mailboxId(), EmailAddress.parse("ceo@other.net")))
        .isFalse();
  }

  @Test
  void enrollmentActivatesWithNewKeyAndStaleVersionsConflict() throws Exception {
    identity.createDomain("example.org");
    Account alice = account("alice@example.org");
    MailboxPublicKey enrolled = key(2);
    Account active = identity.completeEnrollment(alice.mailboxId(), 1, enrolled);
    assertThat(active.state()).isEqualTo(AccountState.ACTIVE);
    assertThat(active.publicKey()).isEqualTo(enrolled);
    assertThat(active.bootstrapExpiresAt()).isNull();
    assertThatThrownBy(() -> identity.completeEnrollment(alice.mailboxId(), 1, key(3)))
        .isInstanceOf(IdentityException.class);
    assertThatThrownBy(() -> identity.changeQuota(alice.mailboxId(), alice.version(), 10))
        .extracting(e -> ((IdentityException) e).reason())
        .isEqualTo(IdentityException.Reason.VERSION_MISMATCH);
    assertThatThrownBy(() -> identity.cutoverPublicKey(alice.mailboxId(), 2, key(2)))
        .isInstanceOf(IllegalArgumentException.class);
  }

  @Test
  void bootstrapLoginExpires() throws Exception {
    identity.createDomain("example.org");
    account("alice@example.org");
    assertThat(identity.loginAccount("alice@example.org")).isPresent();
    clock.advance(Duration.ofDays(2));
    assertThat(identity.loginAccount("alice@example.org")).isEmpty();
  }

  @Test
  void deletedAddressCannotBeRecreatedDuringWaitingPeriodAndGetsNewMailbox() throws Exception {
    identity.createDomain("example.org");
    Account alice = account("alice@example.org");
    Account pending =
        identity.changeState(alice.mailboxId(), alice.version(), AccountState.DELETION_PENDING);
    assertThat(identity.resolveRecipient(alice.address())).isEmpty();
    assertThat(identity.loginAccount("alice@example.org")).isEmpty();
    identity.changeState(alice.mailboxId(), pending.version(), AccountState.DELETED);
    assertThatThrownBy(() -> account("alice@example.org"))
        .extracting(e -> ((IdentityException) e).reason())
        .isEqualTo(IdentityException.Reason.CONFLICT);
    clock.advance(Duration.ofDays(31));
    Account recreated = account("alice@example.org");
    assertThat(recreated.mailboxId()).isNotEqualTo(alice.mailboxId());
    assertThatThrownBy(
            () ->
                identity.createAccount(
                    alice.mailboxId(),
                    EmailAddress.parse("x@example.org"),
                    key(1),
                    0,
                    Duration.ofDays(1)))
        .isInstanceOf(IdentityException.class);
  }

  @Test
  void listenersSeeBlockedAccounts() throws Exception {
    identity.createDomain("example.org");
    Account alice = account("alice@example.org");
    List<AccountState> seen = new java.util.ArrayList<>();
    identity.subscribe((before, after) -> seen.add(after.state()));
    identity.changeState(alice.mailboxId(), alice.version(), AccountState.BLOCKED);
    assertThat(seen).containsExactly(AccountState.BLOCKED);
    assertThat(identity.resolveRecipient(alice.address())).isEmpty();
  }

  @Test
  void canonicalizesAddresses() {
    assertThat(EmailAddress.parse("John.Doe@Bücher.Example").toString())
        .isEqualTo("john.doe@xn--bcher-kva.example");
    for (String bad :
        new String[] {"no-at", "@x.org", "a..b@x.org", "a@localhost", "a b@x.org", "\"q\"@x.org"}) {
      assertThatThrownBy(() -> EmailAddress.parse(bad))
          .isInstanceOf(IllegalArgumentException.class);
    }
  }

  static final class MutableClock extends Clock {
    private Instant now;

    MutableClock(Instant now) {
      this.now = now;
    }

    void advance(Duration duration) {
      now = now.plus(duration);
    }

    @Override
    public java.time.ZoneId getZone() {
      return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(java.time.ZoneId zone) {
      return this;
    }

    @Override
    public Instant instant() {
      return now;
    }
  }
}
