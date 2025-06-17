package org.oa4mp.delegation.common.token;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Interface for creating tokens. Issuers invoke this either either a map that includes the
 * values (as key and value paires), from the servlet request or with a set of strings from which to make the tokens. No arguments in
 * the latter case means a completely new, unused token is created.
 * <p>Created by Jeff Gaynor<br>
 * on 4/10/12 at  11:10 AM
 */

/*
  These all take the same arguments and should
  have similar results, viz., A call with a map will return the given item constructed from the map.
  If the call is made with a servlet request, the parameters of the request are scanned for the information.
  If the call is made with a set of strings, these are used by the forge in sequence of no arguments
  means create a completely new token, one argument creates a token using that string (which is checked for
  any semantics the protocol dictates and is rejected if the string fails) and finally
  a shared secret (if that is supported in the protocol.
 */
public interface TokenForge {
    AuthorizationGrant getAuthorizationGrant(Map<String, String> parameters);
    AuthorizationGrant getAuthorizationGrant(HttpServletRequest request);
    AuthorizationGrant getAuthorizationGrant(String... tokens);

    AccessToken getAccessToken(Map<String, String> parameters);
    AccessToken getAccessToken(HttpServletRequest request);
    AccessToken getAccessToken(String... tokens);

}
