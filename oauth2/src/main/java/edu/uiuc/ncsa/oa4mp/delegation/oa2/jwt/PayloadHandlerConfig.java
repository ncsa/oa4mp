package edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt;

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
