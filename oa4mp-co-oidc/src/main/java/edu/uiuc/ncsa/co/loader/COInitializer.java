package edu.uiuc.ncsa.co.loader;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ServletInitializer;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.OA2ExceptionHandler;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStoreProviders;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SATFactory;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.delegation.storage.impl.ClientConverter;
import edu.uiuc.ncsa.security.servlet.ExceptionHandler;

import javax.servlet.ServletException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/5/16 at  11:33 AM
 */
public class COInitializer extends OA2ServletInitializer {
    @Override
    public ExceptionHandler getExceptionHandler() {
        if (exceptionHandler == null) {
            exceptionHandler = new OA2ExceptionHandler(getEnvironment().getMyLogger());
        }
        return exceptionHandler;
    }

    @Override
    public void init() throws ServletException {
        if (isInitRun) return;
        super.init();
        COSE cose = (COSE) getEnvironment();

        try {
                 SATFactory.setAdminClientConverter(AdminClientStoreProviders.getAdminClientConverter());
                 SATFactory.setClientConverter((ClientConverter<? extends Client>) cose.getClientStore().getACConverter());
             } catch (Exception e) {
                 e.printStackTrace();
             }
    }
}
