package io.github.emotionbug.jdbc.sshj;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder;
import net.schmizz.sshj.connection.channel.direct.Parameters;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import net.schmizz.sshj.userauth.keyprovider.FileKeyProvider;
import net.schmizz.sshj.userauth.keyprovider.OpenSSHKeyFile;
import net.schmizz.sshj.userauth.keyprovider.PuTTYKeyFile;
import net.schmizz.sshj.userauth.method.AuthMethod;
import net.schmizz.sshj.userauth.method.AuthPassword;
import net.schmizz.sshj.userauth.method.AuthPublickey;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@SuppressWarnings("WeakerAccess")
public class SshTunnel extends AbstractTunnel {

  public static final String USERNAME = "username";
  public static final String PASSWORD = "password";
  public static final String PUBLIC_KEY = "public.key.file";
  public static final String PRIVATE_KEY = "private.key.file";
  public static final String PRIVATE_KEY_PASSWORD = "private.key.password";
  public static final String PRIVATE_KEY_FILE_FORMAT = "private.key.file.format";
  public static final String VERIFY_HOSTS = "verify_hosts";
  private static final Logger logger = LoggerFactory.getLogger(SshTunnel.class);
  private final Map<String, String> queryParameters;
  private final String username;
  private final String host;
  private final int port;
  private final Object mutex = new Object();
  private SSHClient client = null;
  private ServerSocket ss = null;
  private Thread runnable;
  private IOException ioe = null;

  public SshTunnel(String sshUrl) throws SQLException {
    super();

    try {
      URI url = new URI(sshUrl.replaceFirst("jdbc:", ""));
      this.queryParameters = splitQuery(url);
      this.port = url.getPort();

      String host = url.getHost();
      String username = queryParameters.get(USERNAME);
      if (username == null || username.length() == 0) {
        if (host.contains("@")) {
          final String[] h = host.split("@");
          username = h[0];
          host = h[1];
        } else if (url.getUserInfo() != null && url.getUserInfo().length() > 0) {
          username = url.getUserInfo();
        } else {
          username = System.getProperty("user.name");
        }
      }
      this.host = host;
      this.username = username;

    } catch (UnsupportedEncodingException | URISyntaxException e) {
      throw new SQLException(e);
    }

    loadDrivers(queryParameters);
    logger.info("Automatic local port assignment starts at: {}:{}", localHost, localPort.get());

  }

  public void start() throws SQLException {
    try {
      client = new SSHClient();
      client.loadKnownHosts();

      boolean verifyHosts = true;
      if (queryParameters.containsKey(VERIFY_HOSTS)) {
        String key = queryParameters.get(VERIFY_HOSTS).toLowerCase();
        if ("false".equals(key) || "0".equals(key) || "off".equals(key)) {
          verifyHosts = false;
        }

        if (!verifyHosts) {
          client.addHostKeyVerifier(new PromiscuousVerifier());
        }
      }

      Runtime.getRuntime().addShutdownHook(new Thread() {
        @Override
        public void run() {
          SshTunnel.this.stop("Shutdown hook.");
        }
      });

      if (this.port > 0) {
        try {
          client.connect(this.host, this.port);
        } catch (java.net.ConnectException e) {
          throw new IOException("Could not connect to SSH on " + this.host + ":" + this.port + "!",
              e);
        }
      } else {
        try {
          client.connect(this.host);
        } catch (IOException e) {
          throw new IOException("Could not connect to SSH on " + this.host + ":22 (default port)!",
              e);
        }
      }

      final List<AuthMethod> methods = new ArrayList<>();

      // Private key authentication
      if (queryParameters.containsKey(PRIVATE_KEY)
          && queryParameters.get(PRIVATE_KEY).length() > 0) {
        String keyFile = queryParameters.get(PRIVATE_KEY);
        // Shell expansion
        keyFile = keyFile.replaceFirst("^~", Matcher.quoteReplacement(System.getProperty("user.home")));

        String keyPassword = queryParameters.get(PRIVATE_KEY_PASSWORD);
        KeyFileFormat keyFileFormat;
        if (queryParameters.get(PRIVATE_KEY_FILE_FORMAT) == null
            || queryParameters.get(PRIVATE_KEY_FILE_FORMAT).length() == 0) {
          if (keyFile.toLowerCase().endsWith(".ppk")) {
            keyFileFormat = KeyFileFormat.PUTTY;
          } else {
            keyFileFormat = KeyFileFormat.OPENSSH;
          }
        } else {
          keyFileFormat = KeyFileFormat
              .valueOf(queryParameters.get(PRIVATE_KEY_FILE_FORMAT).toUpperCase().trim());
        }

        final File privateKey = new File(keyFile);
        if (!privateKey.isFile()) {
          throw new FileNotFoundException("Could not find private key file " + keyFile + "!");
        }

        FileKeyProvider fkp;
        if (keyFileFormat == KeyFileFormat.PUTTY) {
          fkp = new PuTTYKeyFile();
          if (keyPassword != null) {
            fkp.init(privateKey, new PlainPasswordFinder(keyPassword));
          } else {
            fkp.init(privateKey);
          }
        } else {
          OpenSSHKeyFile o = new OpenSSHKeyFile();
          String pubKeyFile = queryParameters.get(PUBLIC_KEY);
          if (pubKeyFile == null || pubKeyFile.length() == 0) {
            pubKeyFile = keyFile + ".pub";
          } else {
            // Shell expansion
            pubKeyFile = pubKeyFile.replaceFirst("^~", Matcher.quoteReplacement(System.getProperty("user.home")));
          }
          final File publicKey = new File(pubKeyFile);
          if (!publicKey.isFile()) {
            if (keyPassword != null) {
              o.init(
                  privateKey,
                  new PlainPasswordFinder(keyPassword)
              );
            } else {
              o.init(privateKey);
            }
          } else {
            if (keyPassword != null) {
              o.init(
                  new String(Files.readAllBytes(privateKey.toPath())),
                  new String(Files.readAllBytes(publicKey.toPath())),
                  new PlainPasswordFinder(keyPassword)
              );
            } else {
              o.init(
                  new String(Files.readAllBytes(privateKey.toPath())),
                  new String(Files.readAllBytes(publicKey.toPath())),
                  null
              );
            }
          }

          fkp = o;
        }

        methods.add(new AuthPublickey(fkp));
      }

      // Add password authentication method
      if (queryParameters.containsKey(PASSWORD)) {
        methods.add(new AuthPassword(new PlainPasswordFinder(queryParameters.get(PASSWORD))));
      }

      logger.info("Connecting to {}:{} with user '{}' and the following authentication methods: {}",
          host, port, username, methods);
      client.auth(username, methods);
      client.getConnection().getKeepAlive().setKeepAliveInterval(30);

      determineLocalPort();
      int localPort = this.localPort.get();

      final Parameters params;
      final String[] remotes = queryParameters.get(REMOTE).split(":", 2);

      params = new Parameters(localHost, localPort, remotes[0],
          Integer.parseInt(remotes[1]));
      logger.debug("Forwarding {}:{} to {}:{}", localHost, localPort, remotes[0], remotes[1]);

      ss = new ServerSocket();
      ss.setReuseAddress(true);
      try {
        ss.bind(new InetSocketAddress(params.getLocalHost(), params.getLocalPort()));
      } catch (BindException e) {
        throw new IOException(
            "Binding to " + params.getLocalHost() + ":" + params.getLocalPort() + " failed!");
      }

      final LocalPortForwarder lpf = client.newLocalPortForwarder(params, ss);

      runnable = new Thread(new Runnable() {
        @Override
        public void run() {
          try {
            lpf.listen();
          } catch (IOException e) {
            ioe = e;
            stop("Exception occurred setting up port forwarder: " + e.getMessage());
            synchronized (mutex) {
              mutex.notify();
            }
          }
        }
      });
      runnable.setDaemon(true);
      runnable.setPriority(Thread.MIN_PRIORITY);
      runnable.start();

      synchronized (mutex) {
        mutex.wait(1000);
      }

      ensureStarted();
    } catch (Exception e) {
      logger.error(e.toString(), e);
      throw new SQLException(e);
    }
  }

  public void ensureStarted() throws SQLException {
    if (ioe != null) {
      throw new SQLException(ioe);
    }
    int wait = 50;
    while ((wait--) > 0 && !isPortOpen(localHost, localPort.get())) {
      try {
        Thread.sleep(100);
      } catch (InterruptedException e) {
        throw new SQLException("Waiting interrupted; probably shutting down...", e);
      }
    }

    if (wait <= 0) {
      throw new SQLException("Port forwarding was not successful!");
    }


  }

  @Override
  boolean isStopped() {
    return runnable == null || ss == null || client == null;
  }

  @Override
  public void stop(String reason) {
    if (runnable != null) {
      runnable.interrupt();
      runnable = null;
      logger.info("Shutting down tunnel {}:{} to {}:{} due to {}", localHost, localPort.get(), host,
          port, reason);
    }

    if (ss != null) {
      try {
        ss.close();
      } catch (IOException e) {
        logger.error("Failed to close socket " + this.ss, e);
      } finally {
        ss = null;
      }
    }

    if (client != null) {
      try {
        client.disconnect();
      } catch (Exception e) {
        // Ignore any errors while disconnecting
      } finally {
        client = null;
      }
      if (logger.isDebugEnabled()) {
        logger.debug("Disconnected.");
      }
    }
  }

  private enum KeyFileFormat {
    PUTTY,
    OPENSSH;
  }
}
