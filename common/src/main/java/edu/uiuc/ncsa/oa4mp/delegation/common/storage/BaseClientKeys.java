package edu.uiuc.ncsa.oa4mp.delegation.common.storage;

import edu.uiuc.ncsa.security.storage.data.MonitoredKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/20/16 at  12:57 PM
 */
public class BaseClientKeys extends MonitoredKeys {
    String debugOn = "debug_on";
    String email = "email";
    String name = "name";
    String secret = "oauth_client_pubkey";
    String jwks = "jwks";
    String kid = "kid";

    public String name(String... x) {
        if (0 < x.length) name = x[0];
        return name;
    }

    public String jwks(String... x) {
        if (0 < x.length) jwks = x[0];
        return jwks;
    }

    public String kid(String... x) {
        if (0 < x.length) kid = x[0];
        return kid;
    }


    public String debugOn(String... x) {
        if (0 < x.length) debugOn = x[0];
        return debugOn;
    }

    public String email(String... x) {
        if (0 < x.length) email = x[0];
        return email;
    }


    public String secret(String... x) {
        if (0 < x.length) secret = x[0];
        return secret;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(name());
        allKeys.add(email());
        allKeys.add(secret());
        allKeys.add(debugOn());
        allKeys.add(jwks());
        allKeys.add(kid());
        return allKeys;
    }
}
