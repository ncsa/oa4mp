package org.oa4mp.server.qdl;

import org.qdl_lang.extensions.QDLLoader;
import org.qdl_lang.module.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  11:36 AM
 */
public class CLCLoader implements QDLLoader {
    @Override
    public List<Module> load() {
        List<Module> modules = new ArrayList<>();
        modules.add(new CLCModule().newInstance(null));
        return modules;
    }

}
