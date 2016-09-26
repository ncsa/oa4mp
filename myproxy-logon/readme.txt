This distribution of the MyProxyLogon may be built in one of two ways.

(1) By invoking ant.

(2) By invoking maven.

Actually, the current distribution only used maven. Invoking ant will simply run the maven build.

These are detailed below. A few conventions.

$MYPROXY = Root for MyProxyLogon source. This readme is in that directory


** Building with Maven **

To simply compile (which will download all of BC automagically) invoke (skipping tests)

mvn clean install

This will tell you it is aborting testing, whcih will happen until you configure the
tests. You can set test properties in the cleverly named
file $MYPROXY/test.properties.

If no host cred is specified, then the tests will not do anything but will pass. This way you can install it
without having to do something bad, like run it as root. You may specify another properties file by passing in
the system property myproxy.test.properties, e.g.

mvn -Dmyproxy.test.properties=/my/very/own/props.properties clean install

The stand-alone jar will be in $MYPROXY/target/MyProxyLogon.jar.

** Building with Ant **

As it stands now, a jar is included in the lib directory which contains the ant tasks to invoke the maven build.
This resolves all dependencies and will even download the latest version of maven
and use that for the build if you do not have maven installed.

The first time you run it, it will download quite a bit, but that should be a one-time affair.