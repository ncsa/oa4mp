package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients;

import edu.uiuc.ncsa.security.delegation.storage.ClientApprovalKeys;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/20/14 at  10:07 AM
 */
public class OA2ClientApprovalKeys extends ClientApprovalKeys {
    public OA2ClientApprovalKeys() {
        super();
        identifier("client_id");
    }
}