package org.shem.app;

import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

/**
 * Command-line entry point.
 *
 * <pre>
 *   shem --config FILE serve          run the configured listeners
 *   shem --config FILE check          validate configuration and data directory
 *   shem --config FILE admin ...      offline administrator management (see AdminCommand)
 *   shem --config FILE backup ...     offline backup and verification (see BackupCommand)
 *   shem --config FILE restore DIR    restore into an empty data directory
 *   shem --config FILE dev ...        local development bootstrap (see DevBootstrapCommand)
 * </pre>
 */
public final class Main {
  private Main() {}

  public static void main(String[] args) throws Exception {
    System.exit(run(Arrays.asList(args)));
  }

  static int run(List<String> args) throws Exception {
    if (args.size() < 3 || !args.get(0).equals("--config")) {
      System.out.println(
          "usage: shem --config FILE <serve | check | admin ... | backup ... | restore DIR | dev ...>");
      return 2;
    }
    ShemConfig config;
    try {
      config = ShemConfig.load(Path.of(args.get(1)));
    } catch (IllegalArgumentException e) {
      System.out.println("invalid configuration: " + e.getMessage());
      return 2;
    }
    List<String> rest = args.subList(2, args.size());
    return switch (rest.get(0)) {
      case "check" -> {
        try (Services services = Services.start(config)) {
          System.out.println(
              "configuration valid; "
                  + services.identity.directory().accounts().size()
                  + " accounts");
        }
        yield 0;
      }
      case "serve" -> {
        java.util.concurrent.CountDownLatch stop = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.CountDownLatch done = new java.util.concurrent.CountDownLatch(1);
        // The hook waits for serve to finish closing listeners, sessions, and workers; otherwise
        // the JVM could halt mid-cleanup (for example leaving worker scratch behind).
        Runtime.getRuntime()
            .addShutdownHook(
                new Thread(
                    () -> {
                      stop.countDown();
                      try {
                        var unused = done.await(30, java.util.concurrent.TimeUnit.SECONDS);
                      } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                      }
                    },
                    "shem-shutdown"));
        try {
          yield new ServeCommand(config, System.out).run(stop);
        } finally {
          done.countDown();
        }
      }
      case "backup" -> new BackupCommand(config, System.out).backup(rest.subList(1, rest.size()));
      case "restore" -> new BackupCommand(config, System.out).restore(rest.subList(1, rest.size()));
      case "admin" ->
          new AdminCommand(config, System.out, DevBootstrapCommand.stdin())
              .run(rest.subList(1, rest.size()));
      case "dev" ->
          new DevBootstrapCommand(config, System.out, DevBootstrapCommand.stdin())
              .run(rest.subList(1, rest.size()));
      default -> {
        System.out.println("unknown command");
        yield 2;
      }
    };
  }
}
