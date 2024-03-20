package io.github.emotionbug.jdbc.sshj;

import java.util.Map;

public class NullUtils {
  public static boolean isNullOrEmpty(String some) {
    return some == null || some.isEmpty();
  }

  public static boolean isNull(Map<String, ?> someMap, String key) {
    return someMap == null || !someMap.containsKey(key);
  }


  public static boolean isNullOrEmpty(Map<String, String> someMap, String key) {
    return isNull(someMap, key) || isNullOrEmpty(someMap.get(key));
  }
}
