package org.oa4mp.server.loader.qdl.claims;

import org.qdl_lang.expressions.module.Module;
import org.qdl_lang.extensions.QDLLoader;

import java.util.ArrayList;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/4/23 at  11:37 AM
 */
public class ClaimsLoader  implements QDLLoader {
    @Override
    public List<Module> load() {
        List<Module> modules = new ArrayList<>();
        modules.add(new ClaimsModule().newInstance(null));
        return modules;
    }}
