package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.OA2LibLoader;
import edu.uiuc.ncsa.oa2.qdl.storage.StoreAccessLoader;
import edu.uiuc.ncsa.qdl.state.State;

/**
 * Instantiated in the {@link edu.uiuc.ncsa.qdl.config.QDLEnvironment} to populate
 * the lib entry. This is never directly used in the code though.
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  9:30 AM
 */
public class OA2LibLoader2 extends OA2LibLoader {
    @Override
    public void add(State state) {
        super.add(state);
        state.addLibEntry(libKey, "cm", CMLoader.class.getCanonicalName());
        state.addLibEntry(libKey, "client", CLCLoader.class.getCanonicalName());
        state.addLibEntry(libKey, "store", StoreAccessLoader.class.getCanonicalName());

    }
}