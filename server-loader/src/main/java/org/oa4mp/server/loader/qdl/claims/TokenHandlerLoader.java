package org.oa4mp.server.loader.qdl.claims;

import org.qdl_lang.extensions.QDLLoader;
import org.qdl_lang.expressions.module.Module;


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
    public List<org.qdl_lang.expressions.module.Module> load() {
        ArrayList<Module> modules = new ArrayList<>();
        modules.add(new TokenHandlerModule().newInstance(null));
        return modules;
    }
}
