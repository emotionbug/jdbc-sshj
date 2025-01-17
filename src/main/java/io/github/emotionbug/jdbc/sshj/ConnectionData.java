package io.github.emotionbug.jdbc.sshj;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author boky
 */
public class ConnectionData {

  private static final Logger log = LoggerFactory.getLogger(ConnectionData.class);

  final String ourUrl;
  final String forwardingUrl;

  public ConnectionData(String ourUrl, String forwardingUrl) {
    this.ourUrl = ourUrl;
    this.forwardingUrl = forwardingUrl;
  }

  public String getOurUrl() {
    return ourUrl;
  }

  public String getForwardingUrl() {
    return forwardingUrl;
  }
}
