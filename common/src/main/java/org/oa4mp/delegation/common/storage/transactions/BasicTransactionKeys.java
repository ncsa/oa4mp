package org.oa4mp.delegation.common.storage.transactions;

import edu.uiuc.ncsa.security.storage.data.SerializationKeys;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/25/12 at  3:10 PM
 */
public class BasicTransactionKeys extends SerializationKeys {
    public BasicTransactionKeys() {
        identifier("temp_token");
    }

    String accessToken = "access_token";
    String authGrant = "auth_grant"; // Changes require that temp_token be used solely as the id.
    String tempCred = "temp_token";

    public String authGrant(String... x) {
        if (0 < x.length) authGrant = x[0];
        return authGrant;
    }


    public String tempCred(String... x) {
        if (0 < x.length) tempCred = x[0];
        return tempCred;
    }

    public String accessToken(String... x) {
        if (0 < x.length) accessToken = x[0];
        return accessToken;
    }

    @Override
    public List<String> allKeys() {
        List<String> allKeys = super.allKeys();
        allKeys.add(tempCred());
        allKeys.add(authGrant());
        allKeys.add(accessToken());
        return allKeys;
    }
}
