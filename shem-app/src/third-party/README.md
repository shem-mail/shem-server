# Supplementary third-party license files

`mvn package` in `shem-app` unpacks the `LICENSE`/`NOTICE` files that the shipped jars carry into
`target/third-party/<artifactId>/`. Some shipped jars carry none, although their license
requires the copyright or notice text to accompany binary redistribution. Those texts live here and
are copied on top, taken from the upstream source at the shipped version:

| Directory | Shipped artifact | Source |
|---|---|---|
| `curvesapi` | `com.github.virtuald:curvesapi:1.08` (BSD-3-Clause) | github.com/virtuald/curvesapi, tag `1.08`, `license.txt` |
| `jose4j` | `org.bitbucket.b_c:jose4j:0.9.6` (Apache-2.0, NOTICE) | bitbucket.org/b_c/jose4j, tag `jose4j-0.9.6`, `NOTICE.txt` |
| `jutf7` | `com.beetstra.jutf7:jutf7:1.0.0` (MIT) | sourceforge.net/p/jutf7, tag `jutf7-1.0.0`, `LICENSE.txt` |
| `jwks-rsa` | `com.auth0:jwks-rsa:0.22.1` (MIT) | github.com/auth0/jwks-rsa-java, tag `0.22.1`, `LICENSE` |
| `jzlib` | `com.jcraft:jzlib:1.1.3` (BSD-3-Clause; its POM says BSD) | github.com/ymnk/jzlib, tag `1.1.3`, `LICENSE.txt` |
| `netty-common` | `io.netty:netty-*:4.1.137.Final` (Apache-2.0, NOTICE) | github.com/netty/netty, tag `netty-4.1.137.Final`, `NOTICE.txt` |
| `protobuf-java` | `com.google.protobuf:protobuf-java:4.33.6` (BSD-3-Clause) | github.com/protocolbuffers/protobuf, tag `v33.6`, `LICENSE` |
| `re2j` | `com.google.re2j:re2j:1.8` (Go License, BSD-3-Clause style) | github.com/google/re2j, tag `re2j-1.8`, `LICENSE` |
| `reactive-streams` | `org.reactivestreams:reactive-streams:1.0.4` (MIT-0) | github.com/reactive-streams/reactive-streams-jvm, tag `v1.0.4`, `LICENSE` |

Apache-2.0 artifacts without an upstream `NOTICE` need no extra file: the license text is the
project's own `LICENSE`. When a dependency is added or upgraded, check `target/third-party/` for an
artifact whose non-Apache license or upstream `NOTICE` is missing and update this directory.
