package io.github.emotionbug.jdbc.sshj;

import static io.github.emotionbug.jdbc.sshj.NullUtils.isNullOrEmpty;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.BindException;
import java.net.ConnectException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import net.schmizz.sshj.SSHClient;
import net.schmizz.sshj.connection.channel.direct.LocalPortForwarder;
import net.schmizz.sshj.connection.channel.direct.Parameters;
import net.schmizz.sshj.transport.TransportException;
import net.schmizz.sshj.transport.verification.PromiscuousVerifier;
import net.schmizz.sshj.userauth.UserAuthException;
import net.schmizz.sshj.userauth.keyprovider.KeyProvider;
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
  private final int port;
  private final Object mutex = new Object();
  private String username;
  private String host;
  private SSHClient client = null;
  private ServerSocket serverSocket = null;
  private Thread localForwarderThread;
  private IOException localForwarderException = null;

  public SshTunnel(String sshUrl) throws SQLException {
    super();
    try {
      URI url = new URI(sshUrl.replaceFirst("jdbc:", ""));
      this.queryParameters = splitQuery(url);
      this.port = url.getPort();
      extractHostAndUsername(url);
    } catch (UnsupportedEncodingException | URISyntaxException e) {
      throw new SQLException(e);
    }
    loadDrivers(queryParameters);
    logger.info("Automatic local port assignment starts at: {}:{}", localHost, localPort.get());
  }

  private void extractHostAndUsername(URI url)
      throws URISyntaxException, UnsupportedEncodingException {
    this.username = extractUsername(url);
    this.host = extractHost(url);
  }

  private String extractUsername(URI url) {
    String username = queryParameters.get(USERNAME);
    String host = url.getHost();

    if (isNullOrEmpty(username)) {
      if (host.contains("@")) {
        final String[] h = host.split("@");
        username = h[0];
      } else if (!isNullOrEmpty(url.getUserInfo())) {
        username = url.getUserInfo();
      } else {
        username = System.getProperty("user.name");
      }
    }

    return username;
  }

  private String extractHost(URI url) {
    String host = url.getHost();

    if (host.contains("@")) {
      final String[] h = host.split("@");
      host = h[1];
    }

    return host;
  }

  public void start() throws SQLException {
    try {
      SSHClient sshClient = initializeSSHClient();
      this.client = sshClient;

      setupShutdownHook();
      connectToHost(sshClient);
      List<AuthMethod> methods = setupPrivateKeyAuthentication(sshClient);
      setupPasswordAuthentication(sshClient, methods);
      initializeConnection(sshClient);
      determineLocalPort();
      int localPort = this.localPort.get();
      final Parameters params = parseRemoteParameters(localPort, queryParameters.get(REMOTE));
      ServerSocket serverSocket = initializeServerSocket(params);
      this.serverSocket = serverSocket;
      createLocalForwarderAndListen(sshClient, params, serverSocket);
    } catch (Exception e) {
      try {
        stop("Failed to start");
      } catch (Exception ignored) {

      }
      logger.error(e.toString(), e);
      throw new SQLException(e);
    }
  }

  private boolean isVerifyHostOff(String key) {
    final String OFF = "off";
    final String ZERO = "0";
    final String FALSE = "false";
    return OFF.equals(key) || ZERO.equals(key) || FALSE.equals(key);
  }

  private SSHClient initializeSSHClient() throws IOException {
    SSHClient client = new SSHClient();
    client.loadKnownHosts();

    boolean verifyHosts = true;
    if (queryParameters.containsKey(VERIFY_HOSTS)) {
      String key = queryParameters.get(VERIFY_HOSTS).toLowerCase();
      if (isVerifyHostOff(key)) {
        verifyHosts = false;
      }

      if (!verifyHosts) {
        client.addHostKeyVerifier(new PromiscuousVerifier());
      }
    }
    return client;
  }

  private void connectToHost(SSHClient sshClient) throws IOException {
    if (this.port > 0) {
      connect(sshClient, this.host, this.port);
    } else {
      connect(sshClient, this.host, SSHClient.DEFAULT_PORT);
    }
  }

  private void connect(SSHClient sshClient, String host, int port) throws IOException {
    try {
      sshClient.connect(host, port);
    } catch (ConnectException e) {
      throw new IOException("Could not connect to SSH on " + host + ":" + port + "!", e);
    }
  }

  private void setupShutdownHook() {
    Runtime.getRuntime().addShutdownHook(new Thread(() -> SshTunnel.this.stop("Shutdown hook.")));
  }

  private List<AuthMethod> setupPrivateKeyAuthentication(
      SSHClient sshClient
  ) throws IOException {
    final List<AuthMethod> methods = new ArrayList<>();
    if (!isNullOrEmpty(queryParameters, PRIVATE_KEY)) {
      String keyFile = getKeyFile();
      String keyPassword = queryParameters.get(PRIVATE_KEY_PASSWORD);
      final KeyFileFormat keyFileFormat = getKeyFileFormat();
      final File privateKey = new File(keyFile);

      if (!privateKey.isFile()) {
        throw new FileNotFoundException("Could not find private key file " + keyFile + "!");
      }

      final KeyProvider fkp =
          getKeyProvider(sshClient, keyFileFormat, privateKey, keyPassword, keyFile);
      methods.add(new AuthPublickey(fkp));
    }
    return methods;
  }

  private KeyFileFormat getKeyFileFormat() {
    KeyFileFormat keyFileFormat;
    if (isNullOrEmpty(queryParameters, PRIVATE_KEY_FILE_FORMAT)) {
      keyFileFormat = null;
    } else {
      keyFileFormat = KeyFileFormat
          .valueOf(queryParameters.get(PRIVATE_KEY_FILE_FORMAT).toUpperCase().trim());
    }
    return keyFileFormat;
  }

  private KeyProvider getKeyProvider(
      SSHClient sshClient,
      KeyFileFormat keyFileFormat,
      File privateKey,
      String keyPassword,
      String keyFile) throws IOException {
    final KeyProvider fkp;
    if (keyFileFormat == KeyFileFormat.PUTTY) {
      PuTTYKeyFile p = new PuTTYKeyFile();
      if (keyPassword != null) {
        p.init(privateKey, new PlainPasswordFinder(keyPassword));
      } else {
        p.init(privateKey);
      }
      fkp = p;
    } else if (keyFileFormat == KeyFileFormat.OPENSSH) {
      String pubKeyFile = queryParameters.get(PUBLIC_KEY);
      if (isNullOrEmpty(pubKeyFile)) {
        pubKeyFile = keyFile + ".pub";
      } else {
        pubKeyFile = pubKeyFile.replaceFirst("^~", System.getProperty("user.home"));
      }
      final File publicKey = new File(pubKeyFile);
      fkp = getOpenSSHFileKeyProvider(publicKey, privateKey, keyPassword);
    } else {
      fkp = getClientKeyProvider(sshClient, keyPassword, keyFile);
    }
    return fkp;
  }

  public boolean isWindowsOperatingSystem() {
    String os = System.getProperty("os.name").toLowerCase();
    return os.contains("win");
  }

  private String getKeyFile() {
    String keyFile = queryParameters.get(PRIVATE_KEY);
    keyFile = keyFile.replaceFirst("^~", System.getProperty("user.home"));
    return keyFile;
  }

  private KeyProvider getOpenSSHFileKeyProvider(File publicKey, File privateKey, String keyPassword)
      throws IOException {
    final OpenSSHKeyFile o = new OpenSSHKeyFile();
    if (!publicKey.isFile()) {
      if (keyPassword != null) {
        o.init(privateKey, new PlainPasswordFinder(keyPassword));
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
    return o;
  }

  private KeyProvider getClientKeyProvider(
      SSHClient sshClient,
      String keyPassword,
      String keyFile) throws IOException {
    final KeyProvider fkp;
    if (keyPassword != null) {
      fkp = sshClient.loadKeys(keyFile, keyPassword);
    } else {
      fkp = sshClient.loadKeys(keyFile);
    }
    return fkp;
  }

  private void setupPasswordAuthentication(SSHClient sshClient, List<AuthMethod> methods)
      throws UserAuthException, TransportException {
    if (queryParameters.containsKey(PASSWORD)) {
      methods.add(new AuthPassword(new PlainPasswordFinder(queryParameters.get(PASSWORD))));
    }
    logConnectionInfo(methods);
    authenticateConnection(sshClient, methods);
  }

  private void logConnectionInfo(List<AuthMethod> methods) {
    logger.info("Connecting to {}:{} with user '{}' and the following authentication methods: {}",
        host, port, username, methods);
  }

  private void authenticateConnection(SSHClient sshClient, List<AuthMethod> methods)
      throws UserAuthException, TransportException {
    sshClient.auth(username, methods);
    sshClient.getConnection().getKeepAlive().setKeepAliveInterval(30);
  }

  private void initializeConnection(SSHClient client) throws IOException {
    client.addHostKeyVerifier(new PromiscuousVerifier());
    client.connect(host, port);
  }

  private Parameters parseRemoteParameters(int localPort, String remoteParam) {
    final String[] remotes = remoteParam.split(":", 2);
    logger.debug("Forwarding {}:{} to {}:{}", localHost, localPort, remotes[0], remotes[1]);
    return new Parameters(localHost, localPort, remotes[0], Integer.parseInt(remotes[1]));
  }

  private ServerSocket initializeServerSocket(Parameters params) throws IOException {
    ServerSocket serverSocket = new ServerSocket();
    serverSocket.setReuseAddress(true);
    try {
      serverSocket.bind(new InetSocketAddress(params.getLocalHost(), params.getLocalPort()));
    } catch (BindException e) {
      try {
        serverSocket.close();
      } catch (Exception ignored) {

      }
      throw new IOException(
          "Binding to " + params.getLocalHost() + ":" + params.getLocalPort() + " failed!");
    }
    return serverSocket;
  }

  private void createLocalForwarderAndListen(SSHClient client, Parameters params,
                                             ServerSocket serverSocket)
      throws InterruptedException, SQLException {
    final LocalPortForwarder lpf = client.newLocalPortForwarder(params, serverSocket);

    Thread localForwarderThread = new Thread(() -> {
      try {
        lpf.listen();
      } catch (IOException e) {
        localForwarderException = e;
        stop("Exception occurred setting up port forwarder: " + e.getMessage());
        synchronized (mutex) {
          mutex.notify();
        }
      }
    });
    this.localForwarderThread = localForwarderThread;

    localForwarderThread.setDaemon(true);
    localForwarderThread.setPriority(Thread.MIN_PRIORITY);
    localForwarderThread.start();
    synchronized (mutex) {
      mutex.wait(1000);
    }
    ensureStarted();
  }

  public void ensureStarted() throws SQLException {
    if (localForwarderException != null) {
      throw new SQLException(localForwarderException);
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
    return localForwarderThread == null || serverSocket == null || client == null;
  }

  @Override
  public void stop(String reason) {
    if (this.localForwarderThread != null) {
      this.localForwarderThread.interrupt();
      this.localForwarderThread = null;
      logger.info("Shutting down tunnel {}:{} to {}:{} due to {}", this.localHost,
          this.localPort.get(), this.host,
          this.port, reason);
    }

    if (this.serverSocket != null) {
      try {
        this.serverSocket.close();
      } catch (IOException e) {
        logger.error("Failed to close socket " + this.serverSocket, e);
      } finally {
        this.serverSocket = null;
      }
    }

    if (this.client != null) {
      try {
        this.client.disconnect();
      } catch (Exception e) {
        // Ignore any errors while disconnecting
      } finally {
        this.client = null;
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
