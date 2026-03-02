package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.storage.monitored.MonitoredKeys;

import java.util.List;

public class KESerializationKeys extends MonitoredKeys {
    protected String alg = "alg";
    protected String isValid = "is_valid";
    protected String exp = "exp";
    protected String iat = "iat";
    protected String is_default = "is_default";
    protected String jwk = "jwk";
    protected String kid = "kid";
    protected String kty = "kty";
    protected String nbf = "nbf";
    protected String use = "key_use"; // can't set it top 'use' since reserved SQL keyword
    protected String vi = "vi";

    @Override
    public List<String> allKeys() {
        List<String> all = super.allKeys();
        all.add(alg());
        all.add(isValid());
        all.add(exp());
        all.add(iat());
        all.add(is_default());
        all.add(jwk());
        all.add(kid());
        all.add(kty());
        all.add(nbf());
        all.add(use());
        all.add(vi());
        return all;
    }

    public KESerializationKeys() {
        super();
        identifier("key_id"); // primary key
    }

    public String alg(String... x) {
        if (0 < x.length) alg = x[0];
        return alg;
    }

    public String isValid(String... x) {
        if (0 < x.length) isValid = x[0];
        return isValid;
    }


    public String exp(String... x) {
        if (0 < x.length) exp = x[0];
        return exp;
    }

    public String iat(String... x) {
        if (0 < x.length) iat = x[0];
        return iat;
    }

    public String is_default(String... x) {
        if (0 < x.length) is_default = x[0];
        return is_default;
    }

    public String jwk(String... x) {
        if (0 < x.length) jwk = x[0];
        return jwk;
    }

    public String kid(String... x) {
        if (0 < x.length) kid = x[0];
        return kid;
    }

    public String kty(String... x) {
        if (0 < x.length) kty = x[0];
        return kty;
    }

    public String nbf(String... x) {
        if (0 < x.length) nbf = x[0];
        return nbf;
    }

    public String use(String... x) {
        if (0 < x.length) use = x[0];
        return use;
    }

    public String vi(String... x) {
        if (0 < x.length) vi = x[0];
        return vi;
    }
}
