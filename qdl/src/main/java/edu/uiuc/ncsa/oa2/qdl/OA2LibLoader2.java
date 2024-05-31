package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2LibLoader;
import edu.uiuc.ncsa.oa2.qdl.storage.StoreAccessLoader;
import edu.uiuc.ncsa.oa2.qdl.testUtils.TestUtilModule;
import edu.uiuc.ncsa.qdl.variables.QDLStem;

/**
 * Instantiated in the {@link edu.uiuc.ncsa.qdl.config.QDLEnvironment} to populate
 * the lib entry. This is never directly used in the code though.
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  9:30 AM
 */
public class OA2LibLoader2 extends OA2LibLoader {

    @Override
    protected QDLStem createEntries() {
        QDLStem lib = super.createEntries();
        QDLStem subLib = new QDLStem();
        subLib.put( "cm", CMLoader.class.getCanonicalName());
        subLib.put( "clc", CLCLoader.class.getCanonicalName());
        subLib.put( "store", StoreAccessLoader.class.getCanonicalName());
        subLib.put( "test_utils", TestUtilModule.class.getCanonicalName());
        lib.put("client", subLib);
        return lib;
    }
}
