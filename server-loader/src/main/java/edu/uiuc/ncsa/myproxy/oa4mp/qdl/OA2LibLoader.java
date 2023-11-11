package edu.uiuc.ncsa.myproxy.oa4mp.qdl;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.acl.ACLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ClaimsLoader;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.util.JWTLoader;
import edu.uiuc.ncsa.qdl.state.LibLoader;
import edu.uiuc.ncsa.qdl.state.State;
import edu.uiuc.ncsa.qdl.variables.QDLStem;

/**
 * Remember that a reference to this class goes into the QDL configuration &lt;modules&gt;
 * tag and its function is to simply put a convenient listing of whatever classes it has
 * into the info().lib entry. 
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  9:20 AM
 */
public class OA2LibLoader implements LibLoader {
    protected String libKey = "oa2";

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
