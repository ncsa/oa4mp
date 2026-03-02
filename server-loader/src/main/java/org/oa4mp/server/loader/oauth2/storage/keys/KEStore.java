package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import org.oa4mp.server.loader.oauth2.storage.vi.VirtualIssuer;

import java.util.HashSet;

public interface KEStore<V extends KERecord> extends Store<V> {
    /** For a given key id (kid) find an return. Key ids are unique in the
     * database. This <i>may</i> be null if there is no such {@link KERecord}.
     * @param kid
     * @return
     */
    KERecord getByKID(String kid);

    /**
     * Get all of the key ids used in this store.
     * @return
     */
    HashSet<String> getKIDs();

    /**
     * Gets the currently active keys for a given virtual issuer. Note that the
     * virtual issuer for the server is  OA2SE#SERVER_VI_ID. A current key is defined as
     * having not expred and being valid.
     * @param vi
     * @return
     */
    JSONWebKeys getCurrentKeys(VirtualIssuer vi);
}
