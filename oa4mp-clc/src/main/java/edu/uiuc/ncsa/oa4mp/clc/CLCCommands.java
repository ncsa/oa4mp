package edu.uiuc.ncsa.oa4mp.clc;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientEnvironment;
import edu.uiuc.ncsa.myproxy.oa4mp.client.OA4MPService;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;

/**
 * Top level class for command line client commands.
 * <p>Created by Jeff Gaynor<br>
 * on 5/11/16 at  1:35 PM
 */
public abstract class CLCCommands extends CommonCommands {
    public CLCCommands(MyLoggingFacade logger, ClientEnvironment ce) {
        super(logger);
        this.ce = ce;
    }

    public ClientEnvironment getCe() {
        return ce;
    }

    public void setCe(ClientEnvironment ce) {
        this.ce = ce;
    }

    protected ClientEnvironment ce;
    OA4MPService service;

    public abstract OA4MPService getService();

    @Override
    public String getPrompt() {
        return "client>";
    }

}
