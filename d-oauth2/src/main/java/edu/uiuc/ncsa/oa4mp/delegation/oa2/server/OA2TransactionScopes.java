package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import net.sf.json.JSONObject;

import java.util.Collection;

/**
 * This contains the bits about scopes for a given transaction. Note that we should have the OA2ServiceTransaction here,
 * but due to inheritance and package issues, that is impossible. Best we can do is abstract what we need to an interface
 * and access that. This permits the {@link AGIResponse2} to figure out if it needs to return a list of scopes in the case
 * that the requested scopes do not match the stored ones. This is for CIL-493.
 * <p>Created by Jeff Gaynor<br>
 * on 7/15/19 at  7:51 PM
 */
public interface OA2TransactionScopes {
    JSONObject getUserMetaData();

    Collection<String> getScopes();
}
