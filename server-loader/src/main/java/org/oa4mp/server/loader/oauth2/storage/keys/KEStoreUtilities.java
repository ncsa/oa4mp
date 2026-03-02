package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;

import java.util.HashSet;

public class KEStoreUtilities {
    public static KERecord getByKID(KEStore store, String kid) {
        //return null;
        throw new NotImplementedException("Implement me!");
    }

    public static HashSet<String> getKIDs(KEStore store) {
        throw new NotImplementedException("Implement me!");
    }
}
