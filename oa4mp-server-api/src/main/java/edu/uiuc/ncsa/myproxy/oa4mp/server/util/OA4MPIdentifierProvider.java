package edu.uiuc.ncsa.myproxy.oa4mp.server.util;

import edu.uiuc.ncsa.security.core.util.IdentifierProvider;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/12 at  3:15 PM
 */
public class OA4MPIdentifierProvider extends IdentifierProvider {

    // These are default creation identifiers. Pass the correct one in the constructor.
    public final static String CLIENT_ID = "client";
    public final static String CLIENT_APPROVAL_ID = "clientApproval";
    public final static String TRANSACTION_ID = "transaction";


    public OA4MPIdentifierProvider(String scheme, String schemeSpecificPart, String component, boolean useTimestamps) {
        super(scheme, schemeSpecificPart, component, useTimestamps);
    }

    public OA4MPIdentifierProvider(String component) {
        super(SCHEME, SCHEME_SPECIFIC_PART, component, true);
    }


}
