package org.oa4mp.delegation.server.storage.support;

import org.oa4mp.delegation.common.storage.transactions.BasicTransactionKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/25/12 at  3:09 PM
 */
public class ServiceTransactionKeys extends BasicTransactionKeys {

    String accessTokenValid = "access_token_valid";
    protected String lifetime = "certlifetime";
    String nonce = "nonce";
    String callbackUri = "oauth_callback";
    String tempCredValid = "temp_token_valid";

    public String lifetime(String... x) {
        if (0 < x.length) lifetime = x[0];
        return lifetime;
    }

    public String callbackUri(String... x) {
        if (0 < x.length) callbackUri = x[0];
        return callbackUri;
    }

    public String tempCredValid(String... x) {
        if (0 < x.length) tempCredValid = x[0];
        return tempCredValid;
    }

    public String accessTokenValid(String... x) {
        if (0 < x.length) accessTokenValid = x[0];
        return accessTokenValid;
    }

    public String nonce(String... x) {
        if (0 < x.length) nonce = x[0];
        return nonce;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(lifetime());
        allKeys.add(callbackUri());
        allKeys.add(tempCredValid());
        allKeys.add(accessTokenValid());
        allKeys.add(nonce());
        return allKeys;
    }
}
