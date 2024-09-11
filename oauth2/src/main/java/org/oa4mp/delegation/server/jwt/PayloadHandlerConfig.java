package org.oa4mp.delegation.server.jwt;

import edu.uiuc.ncsa.security.util.scripting.ScriptSet;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/1/20 at  11:44 AM
 */
public interface PayloadHandlerConfig {
    ScriptSet getScriptSet();

     boolean isLegacyHandler() ;

     void setLegacyHandler(boolean b);
}
