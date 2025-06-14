package org.oa4mp.server.loader.qdl;

import org.oa4mp.server.loader.qdl.acl.ACLoader;
import org.oa4mp.server.loader.qdl.claims.ClaimsLoader;
import org.oa4mp.server.loader.qdl.util.JWTLoader;
import org.qdl_lang.state.LibLoader;
import org.qdl_lang.state.State;
import org.qdl_lang.variables.QDLStem;

import static org.qdl_lang.variables.StemUtility.put;

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
        put(lib,"description", "OA4MP tools for ACLs, JWTs, claims as well as token handlers");
        state.addLibEntries(libKey, createEntries());
    }
    protected QDLStem createEntries(){
        QDLStem lib = new QDLStem();
        put(lib,"description", "OA4MP tools for ACLs, JWTs, claims as well as token handlers");
        QDLStem subLib = new QDLStem();
        put(subLib,"claims", ClaimsLoader.class.getCanonicalName());
        put(subLib,"jwt", JWTLoader.class.getCanonicalName());
        put(subLib,"acl", ACLoader.class.getCanonicalName());
        put(lib,"util", subLib);
        return lib;
    }
}
