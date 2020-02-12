package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.qdl.extensions.QDLFunction;
import edu.uiuc.ncsa.qdl.extensions.QDLLoader;
import edu.uiuc.ncsa.qdl.module.Module;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * This is the class charged with getting all the modules created and is referenced to pull
 * everything in to your workspace.
 * <p>Created by Jeff Gaynor<br>
 * on 2/11/20 at  7:05 AM
 */
public class OA2QDLLoader implements QDLLoader {
    @Override
    public List<Module> load() {
        OA2Module oa2Module = new OA2Module(URI.create("oa2:/qdl/oidc/claims"), "claims");
        ArrayList<QDLFunction> funcs = new ArrayList<>();
        funcs.add(new ClaimsSourceTester());
        funcs.add(new CreateSourceConfig());
        funcs.add(new NewTemplate());
        oa2Module.addFunctions(funcs);
        ArrayList<Module> modules = new ArrayList<>();
        modules.add(oa2Module);
        return modules;
    }
}
