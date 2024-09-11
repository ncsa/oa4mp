package org.oa4mp.server.loader.oauth2.storage.clients;

import org.oa4mp.delegation.common.storage.clients.ClientApprovalKeys;

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