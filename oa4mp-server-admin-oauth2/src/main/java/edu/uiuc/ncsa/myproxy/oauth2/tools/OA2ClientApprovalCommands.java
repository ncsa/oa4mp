package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ClientApprovalStoreCommands;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 4/3/14 at  3:39 PM
 */
public class OA2ClientApprovalCommands extends ClientApprovalStoreCommands {
    public OA2ClientApprovalCommands(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public OA2ClientApprovalCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }


}
