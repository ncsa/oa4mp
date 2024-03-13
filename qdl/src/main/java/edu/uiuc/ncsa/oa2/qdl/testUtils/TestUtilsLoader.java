package edu.uiuc.ncsa.oa2.qdl.testUtils;

import edu.uiuc.ncsa.qdl.extensions.QDLLoader;
import edu.uiuc.ncsa.qdl.module.Module;

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
