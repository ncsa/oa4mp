package org.oa4mp.server.qdl.testUtils;

import org.qdl_lang.extensions.QDLLoader;
import org.qdl_lang.expressions.module.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/11/24 at  8:06 AM
 */
public class TestUtilsLoader implements QDLLoader {
    @Override
    public List<Module> load() {
        List<Module> modules = new ArrayList<>();
        modules.add(new TestUtilModule().newInstance(null));
        return modules;
    }

}
