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
      System.out.println("usage: shem --config FILE <serve | check | dev ...>");
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
        Runtime.getRuntime().addShutdownHook(new Thread(stop::countDown, "shem-shutdown"));
        yield new ServeCommand(config, System.out).run(stop);
      }
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
