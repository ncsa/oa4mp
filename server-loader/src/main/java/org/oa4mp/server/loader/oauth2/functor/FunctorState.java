package org.oa4mp.server.loader.oauth2.functor;

import edu.uiuc.ncsa.security.util.scripting.StateInterface;
import net.sf.json.JSONObject;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/6/20 at  3:36 PM
 */
public class FunctorState implements StateInterface {
    JSONObject claims;
    List<String> scopes;
    JSONObject clientConfig;
}
