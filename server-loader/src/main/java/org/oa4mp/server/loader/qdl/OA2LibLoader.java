package org.oa4mp.server.loader.qdl;

import org.oa4mp.server.loader.qdl.acl.ACLoader;
import org.oa4mp.server.loader.qdl.claims.ClaimsLoader;
import org.oa4mp.server.loader.qdl.util.JWTLoader;
import org.qdl_lang.state.LibLoader;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;

/**
 * Remember that a reference to this class goes into the QDL configuration &lt;modules&gt;
 * tag and its function is to simply put a convenient listing of whatever classes it has
 * into the info().lib entry. 
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  9:20 AM
 */
public class OA2LibLoader implements LibLoader {
    protected String libKey = "oa4mp";

    @Override
    public void add(State state) {
        QDLStem lib = new QDLStem();
        lib.put("description", "OA4MP tools for ACLs, JWTs, claims as well as token handlers");
        state.addLibEntries(libKey, createEntries());
    }
    protected QDLStem createEntries(){
        QDLStem lib = new QDLStem();
        lib.put("description", "OA4MP tools for ACLs, JWTs, claims as well as token handlers");
        QDLStem subLib = new QDLStem();
        subLib.put("claims", ClaimsLoader.class.getCanonicalName());
        subLib.put("jwt", JWTLoader.class.getCanonicalName());
        subLib.put("acl", ACLoader.class.getCanonicalName());
        lib.put("util", subLib);
        return lib;
    }
}
