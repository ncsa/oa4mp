package org.oa4mp.server.proxy.sas;

import edu.uiuc.ncsa.sas.*;
import edu.uiuc.ncsa.sas.loader.SASConfigurationLoader;
import org.apache.commons.configuration.tree.ConfigurationNode;
import org.oa4mp.server.admin.myproxy.oauth2.tools.OA2Commands;
import org.oa4mp.server.api.storage.servlet.MyProxyDelegationServlet;
import org.oa4mp.server.loader.oauth2.OA2SE;

import static edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil.findConfiguration;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/24 at  1:27 PM
 */
public class CLISASServlet extends SASServlet {
    @Override
    public Executable createExecutable(String executableName) {

        OA2SE oa2SE = (OA2SE) MyProxyDelegationServlet.getServiceEnvironment();
        OA2Commands oa2Commands = new OA2Commands(oa2SE.getMyLogger());
        oa2Commands.setEnvironment(oa2SE); // gives it the same runtime as the server.
        StringIO stringIO = new StringIO("");
        SASCLIDriver sascliDriver = new SASCLIDriver(stringIO);
        sascliDriver.addCommands(oa2Commands);
        return sascliDriver;
    }

    @Override
    protected SASEnvironment getSASE() {
        if(sase == null){
            ConfigurationNode node =  findConfiguration("/home/ncsa/dev/csd/config/sas/sat.xml", "oa4mp", "sas");
            SASConfigurationLoader configurationLoader = new SASConfigurationLoader(node);
            sase = configurationLoader.load();
            System.out.println(getClass().getSimpleName() + ":\n" + sase.getClientStore());
        }
        return sase;
    }
}
