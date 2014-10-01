[![Build Status](https://travis-ci.org/propensive/rapture-crypto.png?branch=scala-2.10)](https://travis-ci.org/propensive/rapture-crypto)

# Rapture Crypto

Rapture Crypto provides idiomatic and extensible support for working with cryptography in Scala.

### Status

Rapture Crypto is *experimental*. This means that no API stability is guaranteed, and the API is
liable to be rewritten or discarded at any time.

### Availability

Rapture Crypto 0.10.0 is available under the Apache 2.0 License from Maven Central with group ID `com.propensive` and artifact ID `rapture-crypto_2.10`.

#### SBT

You can include Rapture Crypto as a dependency in your own project by adding the following library dependency to your build file:

```scala
libraryDependencies ++= Seq("com.propensive" %% "rapture-crypto" % "0.10.0")
```

#### Maven

If you use Maven, include the following dependency:

```xml
<dependency>
  <groupId>com.propensive</groupId>
  <artifactId>rapture-crypto_2.10</artifactId>
  <version>0.10.0<version>
</dependency>
```

#### Download

You can download Rapture Crypto directly from the [Rapture website](http://rapture.io/)
Rapture Crypto depends on Scala 2.10 and Rapture Core, but has no other dependencies.

#### Building from source

To build Rapture Crypto from source, follow these steps:

```
git clone git@github.com:propensive/rapture-crypto.git
cd rapture-crypto
sbt package
```

If the compilation is successful, the compiled JAR file should be found in target/scala-2.10
