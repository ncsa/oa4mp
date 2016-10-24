package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.storage.BaseClient;

public class AdminClient extends BaseClient {
    public AdminClient(Identifier identifier) {
        super(identifier);
    }

}