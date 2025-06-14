package org.oa4mp.server.qdl;

import org.oa4mp.server.loader.qdl.OA2LibLoader;
import org.oa4mp.server.qdl.storage.PStoreAccessLoader;
import org.oa4mp.server.qdl.storage.StoreAccessLoader;
import org.oa4mp.server.qdl.testUtils.TestUtilModule;
import org.qdl_lang.config.QDLEnvironment;
import org.qdl_lang.variables.QDLStem;

import static org.qdl_lang.variables.StemUtility.put;

/**
 * Instantiated in the {@link QDLEnvironment} to populate
 * the lib entry. This is never directly used in the code though.
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  9:30 AM
 */
public class OA2LibLoader2 extends OA2LibLoader {
    public static String OA4MP_LIB_KEY = "oa4mp";
    @Override
    protected QDLStem createEntries() {
        QDLStem lib = super.createEntries();
        QDLStem subLib = new QDLStem();
        put(subLib, "cm", CMLoader.class.getCanonicalName());
        put(subLib, "clc", CLCLoader.class.getCanonicalName());
        put(subLib, "store", StoreAccessLoader.class.getCanonicalName());
        put(subLib, "p_store", PStoreAccessLoader.class.getCanonicalName());
        put(subLib, "test_utils", TestUtilModule.class.getCanonicalName());
        put(lib,"client", subLib);
        return lib;
    }
}
