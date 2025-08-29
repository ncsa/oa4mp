package org.oa4mp.server.loader.oauth2.servlet;

import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import org.apache.commons.codec.digest.DigestUtils;

import java.util.HashMap;
import java.util.Map;

/**
 * Typical entry
 * <pre>
 *
 *     &lt;diService enabled="true"&gt;
 *         &lt;users&gt;
 *             &lt;user name="XXX0" hash="YYY0"/&gt;
 *             &lt;user name="XXX1" hash="YYY1"/&gt;
 *         &lt;/users&gt;
 *     &lt;/diService&gt;
 * </pre>
 * <p>Created by Jeff Gaynor<br>
 * on 4/11/23 at  10:55 AM
 */
public class DIServiceConfig {
    public static final String DI_SERVICE_CONFIG_TAG = "diService";
    public static final String DI_SERVICE_ENABLED_ATTRIBUTE = "enabled";
    public static final String DI_SERVICE_USERS_TAG = "users";
    public static final String DI_SERVICE_USER_TAG = "user";
    public static final String DI_SERVICE_NAME_ATTRIBUTE = "username";
    public static final String DI_SERVICE_HASH_ATTRIBUTE = "hash";

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
            throw new UnknownDISericeUserException("unknown db service user \"" + username + "\"");
        }
        String hashed = DigestUtils.sha1Hex(password);
        if(!hashed.equals(getHash(username))){
            throw new UnknownDISericeUserException("incorrect db service password for \"" + username + "\"");
        }

    }
    public void addUser(String username, String hash){
        users.put(username, hash);
    }

    public static class UnknownDISericeUserException extends GeneralException {
        public UnknownDISericeUserException() {
        }

        public UnknownDISericeUserException(Throwable cause) {
            super(cause);
        }

        public UnknownDISericeUserException(String message) {
            super(message);
        }

        public UnknownDISericeUserException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
