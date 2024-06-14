package edu.uiuc.ncsa.oa4mp.installer;

import java.io.File;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/14/24 at  2:53 PM
 */
public class WInstaller extends edu.uiuc.ncsa.security.installer.WebInstaller {
    static protected final String HOST_FLAG = "-host";
    static protected final String PORT_FLAG = "-port";
    public static String NO_PORT = "-1";


    @Override
    protected void setupTemplates() throws IOException {
        super.setupTemplates();
        getTemplates().put("${OA4MP_HOME}", getRoot().getCanonicalPath() + File.separator);
        String h = getHost();
        if (hasPort()) {
            h = h + ":" + getPort();
        }
        getTemplates().put("${OA4MP_HOST}", h);
    }

    @Override
    protected void setupArgMap(String[] args) {
        super.setupArgMap(args);
        for (String arg : args) {
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
    int port = 9443;

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
    public String getLastestConfigFileName() {
        return "/v5_5.yaml";
    }

    @Override
    protected void printMoreHelp() {
        super.printMoreHelp();
        say(HOST_FLAG + " = the host for the service. Default is localhost");
        say(PORT_FLAG + " = the port for the service. Default is 9443. If you set it to -1, no port is used.");
    }

    @Override
    protected void printMoreExamplesHelp() {
        super.printMoreExamplesHelp();
        say(getClass().getSimpleName() + " " + INSTALL_OPTION + " " + ALL_FLAG + " " + DIR_ARG + " $OA4MP_HOME " + HOST_FLAG + " issuer.bgsu.edu" + PORT_FLAG + " -1");
        say("\n\nExample of doing an upgrade");
        say(getClass().getSimpleName() + " " + UPDATE_OPTION + " " + ALL_FLAG + " " + DIR_ARG + " $OA4MP_HOME");
        say("This upgrades all components, but does not touch any .xml (config) files or scripts.\n");
    }
    public static void main(String[] args) {
        try {
            WInstaller wInstaller = new WInstaller();
            wInstaller.init(args);
            if(wInstaller.getArgMap().isShowHelp()){
                wInstaller.showHelp();
                return ;
            }
            wInstaller.process();
            if(wInstaller.getArgMap().isInstall()){
                wInstaller.say("Done! You should add");
                String home = wInstaller.getRoot().getAbsolutePath();
                wInstaller.say("   export OA4MP_HOME=\"" + wInstaller.getRoot().getAbsolutePath() + "\"");
                wInstaller.say("to your environment and");
                wInstaller.say("   $OA4MP_HOME" + File.separator + "bin\"");
                wInstaller.say("to your PATH");
                wInstaller.say("Consider generating server keys by running: ");
                wInstaller.say(home +"/bin/jwt -batch create_keys -out " + home + "/etc/keys.jwk");
                wInstaller.say("When done, select one of the key ids ('kid') in the keys.jwk file for your ");
                wInstaller.say("default server signing key and set it in the defaultKeyID property of the cfg.xml file.");
            }
        } catch (Throwable t) {
            t.printStackTrace();
        }
    }
    public String getAppName(){
        return "OA4MP";
    }
}
