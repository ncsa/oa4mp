package edu.uiuc.ncsa.oa4mp.installer;

import edu.uiuc.ncsa.security.installer.WebInstaller;

import java.io.File;
import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/14/24 at  2:53 PM
 */
public class OA4MPServerInstaller extends WebInstaller {
    static protected final String HOST_FLAG = "-host";
    static protected final String PORT_FLAG = "-port";
    public static String NO_PORT = "-1";


    @Override
    protected Map<String,String> setupTemplates() throws IOException {
        super.setupTemplates();
        // Only process templates if there is a reason to. 
        if(!(getArgMap().isInstall() || getArgMap().isUpgrade() || getArgMap().isRemove())){
            return getTemplates();
        }
        getTemplates().put("${OA4MP_HOME}", getRoot().getCanonicalPath() + File.separator);
        String h = getHost();
        if (hasPort()) {
            h = h + ":" + getPort();
        }
        SecureRandom secureRandom = new SecureRandom();
        byte[] ba = new byte[12];
        secureRandom.nextBytes(ba);
        BigInteger bi = new BigInteger(ba);
        String s=bi.toString(16).toUpperCase();

        getTemplates().put("${JWT_KEY_ID}", s);
        getTemplates().put("${OA4MP_HOST}", h);
        return getTemplates();
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
    protected void printMoreExamplesHelp() throws IOException{
        super.printMoreExamplesHelp();
        say("Example of doing an install");
        say("java -jar installer.jar " + INSTALL_OPTION + " " + DIR_ARG + " $OA4MP_HOME " + HOST_FLAG + " issuer.bgsu.edu" + PORT_FLAG + " -1");
        say("The host for all of the OA4MP endpoints is set to issuer.bgsu.edu");
        say("Compare with");
        say("java -jar installer.jar " + INSTALL_OPTION + " " + DIR_ARG + " $OA4MP_HOME " + HOST_FLAG + " issuer.bgsu.edu");
        say("The host for all of the OA4MP endpoints is set to issuer.bgsu.edu:" + port + "  since that is the default port for SSL.");

        say("\n\nExample of doing an upgrade");
        say("java -jar installer.jar  " + UPDATE_OPTION + " " + DIR_ARG + " $OA4MP_HOME");
        say("This upgrades all components, but does not touch any .xml (config) files or scripts.\n");
    }

    public static void main(String[] args) {
        try {
            OA4MPServerInstaller OA4MPServerInstaller = new OA4MPServerInstaller();
            boolean doProcessing = OA4MPServerInstaller.init(args);
            if (OA4MPServerInstaller.getArgMap().isShowHelp()) {
                OA4MPServerInstaller.showHelp();
                return;
            }
            if(doProcessing){
                OA4MPServerInstaller.process();
            }
            OA4MPServerInstaller.shutdown();

        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

}
