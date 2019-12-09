package edu.uiuc.ncsa.myproxy.oa4mp.server.testing;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl;

/**
 * This is a command line client. It will let you test pretty much the entire life cycle of OAuth. The only thing is you
 * have to have is a client registered with the server.
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  10:34 AM
 */
public abstract class CommandLineClient extends ConfigurableCommandsImpl {
    ClientEnvironment getCE() throws Exception {
        return (ClientEnvironment) getEnvironment();
    }

    public CommandLineClient(MyLoggingFacade logger) {
        super(logger);
    }

    @Override
    public String getComponentName() {
        return ClientXMLTags.COMPONENT;
    }


    @Override
    public void useHelp() {

    }

    @Override
    public String getPrompt() {
        return "test>";
    }
}
