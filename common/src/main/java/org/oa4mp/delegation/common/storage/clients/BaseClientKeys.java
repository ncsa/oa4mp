package org.oa4mp.delegation.common.storage.clients;

import edu.uiuc.ncsa.security.storage.monitored.MonitoredKeys;

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
    String jwksURI = "jwks_uri";
    String rfc7523Client = "rfc7523_client";
    String rfc7523ClientUsers = "rfc7523_client_users";
    String state = "state";

    public String name(String... x) {
        if (0 < x.length) name = x[0];
        return name;
    }

    public String state(String... x) {
        if (0 < x.length) state = x[0];
        return state;
    }

    public String jwks(String... x) {
        if (0 < x.length) jwks = x[0];
        return jwks;
    }
    public String jwksURI(String... x) {
          if (0 < x.length) jwksURI = x[0];
          return jwksURI;
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

    public String rfc7523Client(String... x) {
        if (0 < x.length) rfc7523Client = x[0];
        return rfc7523Client;
    }

    public String rfc7523ClientUsers(String... x) {
        if (0 < x.length) rfc7523ClientUsers = x[0];
        return rfc7523ClientUsers;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(name());
        allKeys.add(email());
        allKeys.add(secret());
        allKeys.add(debugOn());
        allKeys.add(jwks());
        allKeys.add(jwksURI());
        allKeys.add(rfc7523Client());
        allKeys.add(rfc7523ClientUsers());
        allKeys.add(state());
        return allKeys;
    }
}
