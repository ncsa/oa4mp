package edu.uiuc.ncsa.myproxy.oa4mp.qdl;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.acl.ACLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ClaimsLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.util.JWTLoader;
import edu.uiuc.ncsa.qdl.state.LibLoader;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLStem;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  9:20 AM
 */
public class OA2LibLoader implements LibLoader {
    protected String libKey = "oa2";

    @Override
    public void add(State state) {
        QDLStem lib = new QDLStem();
        lib.put("description", "OA4MP tools for ACLs, JWTs, claims as well as token handlers ");
        lib.put("claims", ClaimsLoader.class.getCanonicalName());
        lib.put("jwt", JWTLoader.class.getCanonicalName());
        lib.put("acl", ACLoader.class.getCanonicalName());
        state.addLibEntries(libKey, lib);
    }
}
