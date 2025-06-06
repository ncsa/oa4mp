package org.oa4mp.server.qdl.storage;

import org.qdl_lang.extensions.QDLLoader;
import org.qdl_lang.expressions.module.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/18/20 at  3:28 PM
 */
public class StoreAccessLoader implements QDLLoader {
    @Override
    public List<Module> load() {
        ArrayList<Module> modules = new ArrayList<>();
        modules.add(new StoreAccessModule().newInstance(null));
        return modules;
    }
}
