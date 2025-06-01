package org.oa4mp.server.loader.qdl;

import org.oa4mp.server.loader.qdl.acl.AccessControlModule;
import org.oa4mp.server.loader.qdl.claims.ClaimsModule;
import org.oa4mp.server.loader.qdl.util.JWTModule;
import org.qdl_lang.expressions.module.Module;
import org.qdl_lang.extensions.QDLLoader;

import java.util.ArrayList;
import java.util.List;

/**
 * This is the class charged with getting all the modules created in this Java package
 * and is referenced to pull everything in to your workspace.
 * <p>Created by Jeff Gaynor<br>
 * on 2/11/20 at  7:05 AM
 */
public class OA2QDLLoader implements QDLLoader {
    @Override
    public List<Module> load() {
        ArrayList<Module> modules = new ArrayList<>();
        modules.add(new ClaimsModule().newInstance(null));
        modules.add(new AccessControlModule().newInstance(null));
        modules.add(new JWTModule().newInstance(null));
        return modules;
    }
}
