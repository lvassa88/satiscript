# Satiscript

Script to test the "http signature" authentication type to authorise its clients.

## Table of contents:
* Requirements
* Generate JAR
* Run script

### Requirements:

* java 1.8
* maven (it's optional, because because you can use the maven wrapper)

### Generate JAR:

Run this command:
```
$ mvn clean package
```
or
```
$ ./mvnw clean package
``

(There isn't a test suite. TODO Add)

### Run script:

After generating the package, run the following command (substiture `packagename with generated name):
```
$ java -jar packagename.jar [params]
```

The script provides the following mandatory parameters:
* HTTP method (GET, POST, PUT, DELETE)
* Endpoint to call
* KeyID
* Path of the PrivateKey

This param is mandatory for these HTTP method (POST, PUT):
* Payload
