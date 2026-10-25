package org.shem.mailbox;

import java.security.SecureRandom;
import java.util.Optional;
import java.util.regex.Pattern;
import org.shem.crypto.Secret;

/**
 * Generated credential formats. App passwords are {@code ssss-xxxx-xxxx-xxxx-xxxx-xxxx-xxxx}: a
 * public 4-character slot selector followed by 24 base32 characters (120 bits) of secret. Bootstrap
 * passwords and recovery codes are random base32 groups without a selector.
 */
public final class Credentials {
  private static final char[] ALPHABET = "abcdefghijklmnopqrstuvwxyz234567".toCharArray();
  private static final Pattern APP_PASSWORD = Pattern.compile("[a-z2-7]{4}(-[a-z2-7]{4}){6}");

  private Credentials() {}

  static String randomGroup(SecureRandom random) {
    char[] group = new char[4];
    for (int i = 0; i < group.length; i++) {
      group[i] = ALPHABET[random.nextInt(ALPHABET.length)];
    }
    return new String(group);
  }

  /** Random groups joined with '-', optionally prefixed with a selector group. */
  static Secret generate(SecureRandom random, String prefix, int groups) {
    StringBuilder sb = new StringBuilder(prefix);
    for (int i = 0; i < groups; i++) {
      if (sb.length() > 0) {
        sb.append('-');
      }
      for (int j = 0; j < 4; j++) {
        sb.append(ALPHABET[random.nextInt(ALPHABET.length)]);
      }
    }
    Secret secret = Secret.utf8(sb);
    sb.setLength(0);
    sb.trimToSize();
    return secret;
  }

  /** The selector of an app password, or empty if {@code credential} is not in that format. */
  static Optional<String> appPasswordSelector(CharSequence credential) {
    if (credential.length() != 34 || !APP_PASSWORD.matcher(credential).matches()) {
      return Optional.empty();
    }
    return Optional.of(credential.subSequence(0, 4).toString());
  }

  /** Primary passwords must not look like app passwords, or the login path would be ambiguous. */
  public static boolean isAcceptablePassword(CharSequence password) {
    return password.length() >= 12
        && password.length() <= 1024
        && appPasswordSelector(password).isEmpty();
  }
}
