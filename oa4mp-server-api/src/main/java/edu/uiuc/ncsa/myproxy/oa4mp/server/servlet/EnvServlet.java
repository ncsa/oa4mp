package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceEnvironmentImpl;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;

import java.io.IOException;

/**
 * This servlet loads the environment for all servlets. Any servlet that requires a service environemnt
 * should extend this.
 *
 * <p>Created by Jeff Gaynor<br>
 * on 10/6/16 at  11:43 AM
 */
public abstract class EnvServlet extends AbstractServlet  {

    public ServiceEnvironmentImpl loadProperties2() throws IOException {
        ServiceEnvironmentImpl se2 = (ServiceEnvironmentImpl) getConfigurationLoader().load();
        return se2;
    }


    @Override
    public void loadEnvironment() throws IOException {
        if (environment == null) {
            setEnvironment(loadProperties2());
        }
    }


}
