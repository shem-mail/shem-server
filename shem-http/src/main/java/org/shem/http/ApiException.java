package org.shem.http;

import java.time.Duration;
import org.jspecify.annotations.Nullable;

/** A request failure mapped to an RFC 9457 problem response; messages are safe to return. */
final class ApiException extends Exception {
  private static final long serialVersionUID = 1L;

  final int status;
  final String detail;
  final transient @Nullable Duration retryAfter;

  ApiException(int status, String detail) {
    this(status, detail, null);
  }

  ApiException(int status, String detail, @Nullable Duration retryAfter) {
    super(detail);
    this.detail = detail;
    this.status = status;
    this.retryAfter = retryAfter;
  }

  static ApiException unauthorized() {
    return new ApiException(401, "authentication required or failed");
  }

  static ApiException forbidden() {
    return new ApiException(403, "not permitted for this session");
  }

  static ApiException badRequest(String detail) {
    return new ApiException(400, detail);
  }
}
