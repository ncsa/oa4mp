package edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims;

import edu.uiuc.ncsa.qdl.extensions.QDLLoader;
import edu.uiuc.ncsa.qdl.module.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * This just loads the token handlers. These require an OA2State object to work
 * so cannot really be loaded outside of a running OA4MP instance.
 * <p>Created by Jeff Gaynor<br>
 * on 12/20/21 at  9:12 AM
 */
public class TokenHandlerLoader implements QDLLoader {
    @Override
    public List<Module> load() {
        ArrayList<Module> modules = new ArrayList<>();
        modules.add(new TokenHandlerModule().newInstance(null));
        return modules;
    }
}
