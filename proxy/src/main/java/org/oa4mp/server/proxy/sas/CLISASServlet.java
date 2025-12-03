package org.oa4mp.server.proxy.sas;

import edu.uiuc.ncsa.sas.Executable;
import edu.uiuc.ncsa.sas.SASEnvironment;
import edu.uiuc.ncsa.sas.SASServlet;
import edu.uiuc.ncsa.sas.StringIO;
import edu.uiuc.ncsa.sas.cli.SASCLIDriver;
import edu.uiuc.ncsa.sas.loader.SASCFConfigurationLoader;
import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.cf.CFXMLConfigurations;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.server.admin.oauth2.tools.OA2Commands;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.loader.oauth2.OA2SE;
/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/7/24 at  1:27 PM
 */
public class CLISASServlet extends SASServlet {
    @Override
    public Executable createExecutable(String executableName) {

        OA2SE oa2SE = (OA2SE) OA4MPServlet.getServiceEnvironment();
        StringIO stringIO = new StringIO("");
        SASCLIDriver sascliDriver = null;
        try {
            sascliDriver = new SASCLIDriver(stringIO);
            OA2Commands oa2Commands = new OA2Commands(sascliDriver);
            oa2Commands.setEnvironment(oa2SE); // gives it the same runtime as the server.
            sascliDriver.addCommands(oa2Commands);
            oa2Commands.bootstrap(new InputLine());
        } catch (Throwable e) {
            if(e instanceof RuntimeException){
                throw (RuntimeException) e;
            }
            throw new GeneralException(e);
        }

        return sascliDriver;
    }

    @Override
    protected SASEnvironment getSASE() {
        if(sase == null){
            CFNode node = CFXMLConfigurations.findConfiguration("/home/ncsa/dev/csd/config/sas/sat.xml", "sas", "oa4mp");
            SASCFConfigurationLoader configurationLoader = new SASCFConfigurationLoader(node);

            sase = configurationLoader.load();
            System.out.println(getClass().getSimpleName() + ":\n" + sase.getClientStore());
        }
        return sase;
    }
}
