# Introduction
This project contains schemas used for TA3 serialization.
Those schemas can be written in the versbose 
[Avro schema language](http://avro.apache.org/docs/1.8.0/spec.html) (JSON format),
or they can be written using 
[Avro's IDL specification] (http://avro.apache.org/docs/1.8.0/idl.html) (avdl format).
The IDL is much easier to understand since it is not as
verbose as the json. The Common Data Model (CDM) is specified using the IDL
which is used to automatically generate avsc files.

The json avsc files can be used directly by different serialization APIs.
In addition, classes can be compiled for the Java serialization API
from the schema files.

# Layout
The layout for the project is as follows:
 * Schema files both avdl and generated avsc: [avro/](avro/)
 * Java classes generated from schemas: [src/main/java/com/bbn/tc/schema/avro](src/main/java/com/bbn/tc/schema/avro)
 * Utility code: [src/main/java/com/bbn/tc/schema/utils](src/main/java/com/bbn/tc/schema/utils)
 * Unit tests: [src/test/java/com/bbn/tc/schema/](src/test/java/com/bbn/tc/schema/)

# Updating the CDM version
1. Make edits to the CDM directly in the avdl file CDM`xx`.avdl, where `xx` is the version number
2. If the CDM version changes, then we create a new file CDM`yy`.avdl, where `yy` is the new version number
3. Update the [pom.xml](pom.xml) property `CDM-IDL-FILE` to point to the new `yy` version. For example,
```
<CDM-IDL-FILE>CDM06.avdl</CDM-IDL-FILE>
```

# Installation
## Schema file and Java bindings
To install using maven, first we create the avsc schema files from the avdl file using the `exec:java`.
Then we install which auto runs the unit tests.
```
mvn clean exec:java
mvn install
```
Note that `exec:java` will run the idl2schemata from avro-tools which is not well designed.
The tool has a `System.exit()` which halts the JVM (and the maven process) but that's ok.

## C++ bindings
To generate the C++ bindings, run the following:
```
sudo mvn compile -Pcpp
```
The sudo is required because we install the generated sources to `/usr/local/include`.
Note that we expect that the schema file has already been generated by the above steps.