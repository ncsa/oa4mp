package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.security.core.Store;

import java.util.List;

/**
 * Certain cases in the OIDC spec (such as getting the id token back as a hint)
 * requiring checking that the user so named has an active logon. That means that
 * there must be a pending transaction.
 * <p>Created by Jeff Gaynor<br>
 * on 11/25/15 at  12:05 PM
 */
public interface UsernameFindable<V extends OA2ServiceTransaction> extends Store<V> {
    // There are in general multiple transactions for a given user name.
    List<V> getByUsername(String username);
}
