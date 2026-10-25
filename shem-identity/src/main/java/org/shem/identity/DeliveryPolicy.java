package org.shem.identity;

/**
 * Which account states accept mail. Default: active accounts and accounts awaiting enrollment (the
 * latter is a documented exposure: mail delivered before enrollment is sealed to the bootstrap key,
 * which the administrator who issued the bootstrap credential could unwrap).
 */
public record DeliveryPolicy(boolean acceptBeforeEnrollment, boolean acceptWhileBlocked) {
  public static final DeliveryPolicy DEFAULT = new DeliveryPolicy(true, false);

  public boolean accepts(AccountState state) {
    return switch (state) {
      case ACTIVE -> true;
      case PENDING_ENROLLMENT -> acceptBeforeEnrollment;
      case BLOCKED -> acceptWhileBlocked;
      case DELETION_PENDING, DELETED -> false;
    };
  }
}
