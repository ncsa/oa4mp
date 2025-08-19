package org.oa4mp.server.loader.oauth2.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Typical entry
 * <pre>
 *
 *     &lt;dbService enabled="true"&gt;
 *         &lt;users&gt;
 *             &lt;user name="XXX0" hash="YYY0"/&gt;
 *             &lt;user name="XXX1" hash="YYY1"/&gt;
 *         &lt;/users&gt;
 *     &lt;/dbService&gt;
 * </pre>
 * <p>Created by Jeff Gaynor<br>
 * on 4/11/23 at  10:55 AM
 */
public class DBServiceConfig {
    public static final String DB_SERVICE_CONFIG_TAG = "dbService";
    public static final String DB_SERVICE_ENABLED_ATTRIBUTE = "enabled";
    public static final String DB_SERVICE_USERS_TAG = "users";
    public static final String DB_SERVICE_USER_TAG = "user";
    public static final String DB_SERVICE_NAME_ATTRIBUTE = "username";
    public static final String DB_SERVICE_HASH_ATTRIBUTE = "hash";

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    boolean enabled = false;

    Map<String, String> users = new HashMap<>();
    public boolean hasUsers(){
        return !users.isEmpty();
    }
    public boolean hasUser(String username){
        return users.containsKey(username);
    }
    public String getHash(String username){
        return users.get(username);
    }
    public void checkPassword(String username, String password){
        if(!hasUser(username)){
            throw new UnknownDBSericeUserException("unknown db service user \"" + username + "\"");
        }
        String hashed = DigestUtils.sha1Hex(password);
        if(!hashed.equals(getHash(username))){
            throw new UnknownDBSericeUserException("incorrect db service password for \"" + username + "\"");
        }

    }
    public void addUser(String username, String hash){
        users.put(username, hash);
    }

    public static class UnknownDBSericeUserException extends GeneralException {
        public UnknownDBSericeUserException() {
        }

        public UnknownDBSericeUserException(Throwable cause) {
            super(cause);
        }

        public UnknownDBSericeUserException(String message) {
            super(message);
        }

        public UnknownDBSericeUserException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
