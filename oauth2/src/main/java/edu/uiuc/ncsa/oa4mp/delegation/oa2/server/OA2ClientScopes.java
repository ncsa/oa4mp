package edu.uiuc.ncsa.oa4mp.delegation.oa2.server;

import java.util.Collection;

/**
 * This abstracts the scopes stored in the client so a propert {@link AGIResponse2} can be created.  This is for CIL-493.
 * <p>Created by Jeff Gaynor<br>
 * on 7/15/19 at  7:51 PM
 */
public interface OA2ClientScopes {
    public Collection<String> getScopes();
}
