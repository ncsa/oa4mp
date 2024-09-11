package org.oa4mp.server.proxy.sas;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.api.storage.servlet.MyProxyDelegationServlet;
import org.oa4mp.server.admin.myproxy.oauth2.tools.OA2Commands;
import edu.uiuc.ncsa.sas.Executable;
import edu.uiuc.ncsa.sas.SASCLIDriver;
import edu.uiuc.ncsa.sas.SASServlet;
import edu.uiuc.ncsa.sas.StringIO;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/24 at  1:27 PM
 */
public class CLISASServlet extends SASServlet {
    @Override
    public Executable createExecutable(String executableName) {
        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        OA2Commands oa2Commands = new OA2Commands(oa2SE.getMyLogger());
        StringIO stringIO = new StringIO("");
        SASCLIDriver sascliDriver = new SASCLIDriver(stringIO);
        sascliDriver.addCommands(oa2Commands);
        return sascliDriver;
    }
}
