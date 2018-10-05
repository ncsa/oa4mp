package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.myproxy.oa4mp.loader.OA4MPConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.core.util.LoggingConfigLoader;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import org.apache.commons.lang.StringUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/22/13 at  4:49 PM
 */
public class OA4MPCommands extends BaseCommands {
    public OA4MPCommands(MyLoggingFacade logger) {
        super(logger);
    }


    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        return new OA4MPConfigurationLoader<ServiceEnvironmentImpl>(getConfigurationNode());
    }

    @Override
    public String getPrompt() {
        return "oa4mp >";
    }



    public void about() {
        int width = 60;
        String stars = StringUtils.rightPad("", width + 1, "*");
        say(stars);
        say(padLineWithBlanks("* OA4MP CLI (Command Line Interpreter)", width) + "*");
        say(padLineWithBlanks("* Version " + LoggingConfigLoader.VERSION_NUMBER, width) + "*");
        say(padLineWithBlanks("* By Jeff Gaynor  NCSA", width) + "*");
        say(padLineWithBlanks("*  (National Center for Supercomputing Applications)", width) + "*");
        say(padLineWithBlanks("*", width)+"*");
        say(padLineWithBlanks("* type 'help' for a list of commands", width) + "*");
        say(padLineWithBlanks("*      'exit' or 'quit' to end this session.", width) + "*");
        say(padLineWithBlanks("*      '/h' to print the command history, /r to repeat the last command.", width) + "*");
        say(stars);
    }




    public static void main(String[] args) {
        try {
            OA4MPCommands OA4MPCommands = new OA4MPCommands(null);
            OA4MPCommands.start(args);
            if (OA4MPCommands.executeComponent()) {
                return;
            }
            CLIDriver cli = new CLIDriver(OA4MPCommands);
            cli.start();
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }







    public ClientStoreCommands getNewClientStoreCommands() throws Exception {
        return new ClientStoreCommands(getMyLogger(), "  ", getServiceEnvironment().getClientStore(), getServiceEnvironment().getClientApprovalStore());
    }



    public CopyCommands getNewCopyCommands() throws Exception {
        return new CopyCommands(getMyLogger(), new CopyTool(), new CopyToolVerifier(), getConfigFile());
    }


}
