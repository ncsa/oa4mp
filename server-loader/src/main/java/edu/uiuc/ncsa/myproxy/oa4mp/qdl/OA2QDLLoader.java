package edu.uiuc.ncsa.myproxy.oa4mp.qdl;

import edu.uiuc.ncsa.myproxy.oa4mp.qdl.acl.AccessControlModule;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ClaimsModule;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.util.JWTModule;
import edu.uiuc.ncsa.qdl.extensions.QDLLoader;
import edu.uiuc.ncsa.qdl.module.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * This is the class charged with getting all the modules created and is referenced to pull
 * everything in to your workspace.  This is a convenience for one-stop shopping of OA4MP
 * tools.
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
