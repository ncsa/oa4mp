package edu.uiuc.ncsa.oa2.qdl;

import edu.uiuc.ncsa.qdl.extensions.JavaModule;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/10/20 at  5:49 AM
 */
public class OA2Module extends JavaModule {
    @Override
     public boolean isExternal() {
         return true;
     }

    public OA2Module(URI namespace, String alias) {
        super(namespace, alias);
    }
    
}
