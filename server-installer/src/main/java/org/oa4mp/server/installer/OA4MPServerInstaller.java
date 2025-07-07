package org.oa4mp.server.installer;

import org.oa4mp.installer.AbstractInstaller;

import java.io.IOException;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/14/24 at  2:53 PM
 */
public class OA4MPServerInstaller extends AbstractInstaller {
    static protected final String HOST_FLAG = "-host";
    static protected final String PORT_FLAG = "-port";

    public static String NO_PORT = "-1";

    @Override
    protected Map<String, String> setupTemplates() throws IOException {
        super.setupTemplates();
        // Only process templates if there is a reason to. 
        if (!(getArgMap().isInstall() || getArgMap().isUpgrade() || getArgMap().isRemove())) {
            return getTemplates();
        }
        String h = getHost();
        if (hasPort()) {
            h = h + ":" + getPort();
        }

        getTemplates().put("${OA4MP_HOST}", h);
        return getTemplates();
    }

    @Override
    public String getStoreTileDirectory() {
        return "/tiles/";
    }

    @Override
    protected void setupArgMap(String[] args) {
        super.setupArgMap(args);
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case HOST_FLAG:
                    getArgMap().put(HOST_FLAG, arg);
                    break;
                case PORT_FLAG:
                    getArgMap().put(PORT_FLAG, arg);
                    break;
            }
        }
    }

    protected String getHost() {
        if (getArgMap().containsKey(HOST_FLAG)) {
            return (String) getArgMap().get(HOST_FLAG);
        }
        return host;
    }

    String host = "localhost";
    int port = 8443;

    protected boolean hasPort() {
        if (!getArgMap().containsKey(PORT_FLAG)) return true; // means they get the default
        return !getArgMap().get(PORT_FLAG).equals(NO_PORT);
    }

    protected int getPort() {
        if (getArgMap().containsKey(PORT_FLAG)) {
            return Integer.parseInt((String) getArgMap().get(PORT_FLAG));
        }
        return port;
    }

    @Override
    protected void printMoreArgHelp() throws IOException {
        super.printMoreArgHelp();
        say(HOST_FLAG + " = the host for the service. Default is localhost");
        say(PORT_FLAG + " = the port for the service. Default is " + port + ". If you set it to -1, no port is used.");
    }

    @Override
    protected void printMoreExamplesHelp() throws IOException {
        super.printMoreExamplesHelp();
        say("Example of doing an install");
        say("java -jar installer.jar " + INSTALL_OPTION + " " + DIR_ARG + " $OA4MP_HOME " + HOST_FLAG + " issuer.bgsu.edu" + PORT_FLAG + " -1");
        say("The host for all of the OA4MP endpoints is set to issuer.bgsu.edu");
        say("Compare with");
        say("java -jar installer.jar " + INSTALL_OPTION + " " + DIR_ARG + " $OA4MP_HOME " + HOST_FLAG + " issuer.bgsu.edu");
        say("The host for all of the OA4MP endpoints is set to issuer.bgsu.edu:" + port + "  since that is the default port for SSL.");

        say("\n\nExample of doing an upgrade");
        say("java -jar installer.jar  " + UPGRADE_OPTION + " " + DIR_ARG + " $OA4MP_HOME");
        say("This upgrades all components, but does not touch any .xml (config) files or scripts.");
        say("Note that " + UPDATE_OPTION + " is a synonym");
        say("\n\nExample of preparing an extension file for preprocessing. ");
        say("This is used if you want to apply scripts to the server right after boot, for instance.");
        say("Your file should use the template of ${OA4MP_HOME} every place it needs to refer to the");
        say("(new) installation. So the example might be a QDL ini file that needs the path to the current");
        say("server configuration to do some setup before starting the server:");
        say("[cfg]");
        say("file := '${OA4MP_HOME}etc/cfg.xml';");
        say("name := 'default';");
    }

    public static void main(String[] args) {
        try {
            OA4MPServerInstaller OA4MPServerInstaller = new OA4MPServerInstaller();
            boolean doProcessing = OA4MPServerInstaller.init(args);
            if (OA4MPServerInstaller.getArgMap().isShowHelp()) {
                OA4MPServerInstaller.showHelp();
                return;
            }
            if (doProcessing) {
                OA4MPServerInstaller.process();
                if(OA4MPServerInstaller.getArgMap().isInstall()){
                    OA4MPServerInstaller.say(OA4MPServerInstaller.getMessage("/oa4mp/success.txt"));
                }
            }
            OA4MPServerInstaller.shutdown();

        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    @Override
    protected String getDerbySetupScriptPath() {
        return getTemplates().get("${OA4MP_HOME}") + "etc/oa4mp-derby.sql";

    }
}
