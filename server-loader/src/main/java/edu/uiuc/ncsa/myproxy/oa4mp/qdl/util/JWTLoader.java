package edu.uiuc.ncsa.myproxy.oa4mp.qdl.util;

import edu.uiuc.ncsa.qdl.extensions.QDLLoader;
import edu.uiuc.ncsa.qdl.module.Module;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  11:38 AM
 */
public class JWTLoader  implements QDLLoader {
    @Override
    public List<Module> load() {
        List<Module> modules = new ArrayList<>();
        modules.add(new JWTModule().newInstance(null));
        return modules;
    }}
