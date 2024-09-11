package org.oa4mp.server.qdl;

import org.oa4mp.server.loader.qdl.util.JWTModule;
import org.oa4mp.server.qdl.testUtils.TestUtilModule;
import org.qdl_lang.extensions.QDLLoader;
import org.qdl_lang.module.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * This is the class charged with getting all the modules created and is referenced to pull
 * everything in to your workspace.
 * <p>Created by Jeff Gaynor<br>
 * on 2/11/20 at  7:05 AM
 */
public class QDLToolsLoader implements QDLLoader {
    @Override
    public List<Module> load() {
        ArrayList<Module> modules = new ArrayList<>();
        modules.add(new JWTModule().newInstance(null));
        modules.add(new ClientManagementModule().newInstance(null));
        modules.add(new CLCModule().newInstance(null));
        modules.add(new TestUtilModule().newInstance(null));
        return modules;
    }
}
