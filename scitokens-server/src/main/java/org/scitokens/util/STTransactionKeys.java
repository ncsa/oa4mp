package org.scitokens.util;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  11:05 AM
 */
public class STTransactionKeys extends OA2TransactionKeys {
    protected String sciTokens="sci_tokens";

    public String sciTokens(String... x) {
         if (0 < x.length) sciTokens = x[0];
         return sciTokens;
     }

    protected String stScopes = "st_scopes";

    public String stScopes(String... x) {
         if (0 < x.length) stScopes= x[0];
         return stScopes;
     }

}
