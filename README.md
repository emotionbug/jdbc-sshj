# jdbc-sshj

A JDBC Driver Wrapper which connects over SSH to the target database. Please note that only one port is fowarded, so
forget about connecting to Oracle on Windows.

This project was created using code from [jdbc-ssh](https://github.com/monkeysintown/jdbc-ssh) but the underlying
implementation of SSH has been switched from [JSch](http://www.jcraft.com/jsch/) to
[SSHJ](https://github.com/hierynomus/sshj) which seems to be updated more frequently, and knows how to connect to newer
encryption standards of SSH.

The Driver will by default load your `known_hosts` file and will refuse to connect if the host is not in the list. To
supress this behaviour, set `verify_hosts=off`.

## Usage

Usage is simple:

- drop the JAR into your project (or include it as maven dependency)
- prepend with "jdbc:sshj:" or "jdbc:sshj-native:" command string before your URL
- put the placeholder `{{port}}` in your old JDBC url.

### Syntax

There are two versions of this driver: the *JDBC-SSHJ*, which uses
buit-in [SSH client](https://github.com/hierynomus/sshj) and *JDBC-SSHJ-NATIVE*, which spins off local `ssh` session.
Each has its own advantages and downfalls:

- *SSHJ* is more cross-platform and does not depend on any libraries
- *SSHJ-NATIVE* can support newer OpenSSH features and can use your `.ssh/config` but it's not cross-platform. Windows
  users, beware.

The JDBC-SSHJ uses the following syntax:

```
jdbc:sshj://[user@]<host>[:<port>]
   ?remote=<host:port>
	[&username=<ssh username>]
	[&password=<ssh password>]
	[&private.key.file=<location of your private key file>]
	[&private.key.password=<password for the private key>]
	[&private.key.file.format=(PUTTY|OPENSSH)]
	[&verify_hosts=(on|off)]
	;;;
	<your-original-url-with-{{port}}>
```

| Parameter                     | Description                                                                                                                                              | Example                        |
|-------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------|
| *jdbc:sshj://<host>[:<port>]* | The *host* and *port* of the remote SSH server. Port is optional.                                                                                        | `jdbc:sshj://demo.example.org` |
| *remote*                      | The *host* and *port* of the database on the remote server.                                                                                              | `10.11.12.13:5432`             |
| *username*                    | The SSH username. Alternatively, specify it before the `@` sign in the host name                                                                         | `demo`                         |
| *password*                    | The SSH password, if you want to try password authentication.                                                                                            | `demo123`                      |
| *public.key.file*             | Path to the file with the public key. Sometimes needed if not embedded in private key or not on assumed location.                                        | `~/.ssh/id_rsa.pub`            |
| *private.key.file*            | Path to the file with a private key.                                                                                                                     | `~/.ssh/id_rsa`                |
| *private.key.password*        | Password for the private key, if any.                                                                                                                    | `demo1234`                     |
| *private.key.file.format*     | Optional private key file format. `PUTTY` or `OPENSSH` are accepted, mainly for backward compatibility. If omitted (recommended) let SshJ detect format. | `PUTTY`                        | 
| *drivers*                     | Comma separated list of drivers (class files) to preload.                                                                                                | `org.postgresql.Driver`        | 
| *verify_hosts*                | Suppress host verification. Driver will not complain on new/unknown hosts.                                                                               | `off`                          | 

The JDBC-SSHJ NATIVE uses the following syntax:

```
jdbc:sshj-native://<any-parameters-which-you-might-send-to-ssh>
   ?remote=<[user@]host:port>
   ?keepalive.command=<remote_command>
	;;;
	<your-original-url-with-{{port}}>
```

| Parameter                                    | Description                                                                                              | Example                       |
|----------------------------------------------|----------------------------------------------------------------------------------------------------------|-------------------------------|
| *any-parameters-which-you-might-send-to-ssh* | Anything you type here is going to be echoed directly to the SSH command                                 | `-c demo@demo.example.org -r` | 
| *keepalive.command*                          | Command to run on the remote server to keep the session alive. If not set, your session *might* timeout. | `ping localhost`              |

Please note that the driver will open a local port and forward it to the server. It will inject the local host and port
into your original JDBC URL when it sees the text `{{host}}` and `{{port}}`, respectively.

Driver will listen on a local IP in the range from 127.0.1.2 - 127.0.1.200 and a random port in the range of
20000 - 20110. On OS X, though, only 127.0.0.1 is used, as Mac by default doesn't listen to anything else than this IP.
See
[StackOverflow](https://superuser.com/questions/458875/how-do-you-get-loopback-addresses-other-than-127-0-0-1-to-work-on-os-x)
for more details on this.

### Example

If your original URL was:

```
jdbc:postgresql://10.10.11.11:5432/demo-1?ssl=true&allowEncodingChanges=true
```

And you need to connect to this server from the outside, change it like this (split into lines for legibility):

```
jdbc:sshj://demo.example.org
	?username=admin
	&private.key.file=~/.ssh/id_rsa
	&private.key.password=admin12345
	&remote=10.10.11.11:5432
	;;;
	jdbc:postgresql://{{host}}:{{port}}/demo-1?ssl=true&allowEncodingChanges=true
```

## Build

If you just want to compile the project without running the tests:

```
./gradlew clean build
```

If you want to run the tests (Derby and H2 in server mode):

```
./gradlew clean test
```

## Dependencies

You can set up your dependencies like this:

- Maven
  ```xml
  <dependency>
    <groupId>io.github.emotionbug</groupId>
    <artifactId>jdbc-sshj</artifactId>
    <version>1.0.13</version>
  </dependency>
  ```

- Gradle
  ```kotlin 
  implementation("io.github.emotionbug:jdbc-sshj:1.0.13")
  ```

## Copyright

This project cloned from below repositories.

https://github.com/bokysan/jdbc-sshj

https://github.com/monkeysintown/jdbc-ssh

## TODO

- Discover why Derby test for SSH native connection is failing.
