package org.oa4mp.server.loader.oauth2.cm.util.admin;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.cm.util.AbstractDDServer;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/17/17 at  10:48 AM
 */
public class AdminClientServer extends AbstractDDServer {
    public AdminClientServer(OA2SE cose) {
        super(cose);
    }

    public AbstractACResponse get(ACGetRequest request) {
        if(request.getAdminClient().getIdentifierString().length() == 0){
            throw new GeneralException("Error: No supplied admin client identifier.");
        }
        AdminClient adminClient = getAdminClientStore().get(request.getAdminClient().getIdentifier());
        adminClient.setSecret(""); // do not return the secret or its hash
        return new ACGetResponse(adminClient, cose.getClientApprovalStore().isApproved(adminClient.getIdentifier()));
    }
}
