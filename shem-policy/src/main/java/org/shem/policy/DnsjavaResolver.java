package org.shem.policy;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.xbill.DNS.AAAARecord;
import org.xbill.DNS.ARecord;
import org.xbill.DNS.Cache;
import org.xbill.DNS.DClass;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.MXRecord;
import org.xbill.DNS.Name;
import org.xbill.DNS.PTRRecord;
import org.xbill.DNS.Record;
import org.xbill.DNS.ResolverConfig;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.TextParseException;

/**
 * dnsjava resolver with a private bounded cache (never dnsjava's process-wide default cache) and a
 * per-query timeout. Uses the system resolver configuration unless servers are given.
 */
public final class DnsjavaResolver implements DnsResolver {
  /** At most this many records of one answer are returned. */
  static final int MAX_RECORDS = 32;

  private final ExtendedResolver resolver;
  private final Cache cache;

  public DnsjavaResolver(
      List<String> servers, Duration timeout, int maxCacheEntries, Duration maxTtl)
      throws UnknownHostException {
    if (servers.isEmpty()) {
      List<String> system = new ArrayList<>();
      ResolverConfig.getCurrentConfig().servers().forEach(s -> system.add(s.getHostString()));
      this.resolver = new ExtendedResolver(system.toArray(String[]::new));
    } else {
      this.resolver = new ExtendedResolver(servers.toArray(String[]::new));
    }
    resolver.setTimeout(timeout);
    resolver.setRetries(1);
    this.cache = new Cache(DClass.IN);
    cache.setMaxEntries(maxCacheEntries);
    cache.setMaxCache((int) maxTtl.toSeconds());
    cache.setMaxNCache((int) Math.min(maxTtl.toSeconds(), 900));
  }

  @Override
  public List<String> lookup(String name, Type type) throws DnsTemporaryException {
    Lookup lookup;
    try {
      // Absolute names: the search path never applies.
      lookup = new Lookup(Name.fromString(name, Name.root), code(type), DClass.IN);
    } catch (TextParseException e) {
      return List.of();
    }
    lookup.setResolver(resolver);
    lookup.setCache(cache);
    Record[] records = lookup.run();
    switch (lookup.getResult()) {
      case Lookup.SUCCESSFUL -> {}
      case Lookup.HOST_NOT_FOUND, Lookup.TYPE_NOT_FOUND -> {
        return List.of();
      }
      default -> throw new DnsTemporaryException("dns " + type + " lookup failed");
    }
    List<String> result = new ArrayList<>();
    for (Record record : records) {
      if (result.size() >= MAX_RECORDS) {
        break;
      }
      switch (record) {
        case ARecord a -> result.add(a.getAddress().getHostAddress());
        case AAAARecord a -> result.add(a.getAddress().getHostAddress());
        case MXRecord mx -> {
          String target = mx.getTarget().toString(true);
          result.add(mx.getPriority() + " " + (target.isEmpty() ? "." : target));
        }
        case PTRRecord ptr -> result.add(ptr.getTarget().toString(true));
        case TXTRecord txt -> result.add(String.join("", txt.getStrings()));
        default -> {}
      }
    }
    return List.copyOf(result);
  }

  private static int code(Type type) {
    return switch (type) {
      case A -> org.xbill.DNS.Type.A;
      case AAAA -> org.xbill.DNS.Type.AAAA;
      case MX -> org.xbill.DNS.Type.MX;
      case PTR -> org.xbill.DNS.Type.PTR;
      case TXT -> org.xbill.DNS.Type.TXT;
    };
  }
}
