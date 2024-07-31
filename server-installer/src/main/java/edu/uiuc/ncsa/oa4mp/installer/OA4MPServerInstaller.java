package edu.uiuc.ncsa.oa4mp.installer;

import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.installer.WebInstaller;
import org.apache.commons.codec.binary.Base64;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/14/24 at  2:53 PM
 */
public class OA4MPServerInstaller extends WebInstaller {
    static protected final String HOST_FLAG = "-host";
    static protected final String PORT_FLAG = "-port";
    static protected final String STORE_FLAG = "-store";
    static protected final String STORE_TYPE_DERBY_FILE = "derby_file";
    static protected final String STORE_TYPE_FILE_STORE = "file_store";
    static protected final String STORE_TYPE_MYSQL = "mysql";
    static protected final String STORE_TYPE_MARIA_DB = "mariadb";
    static protected final String STORE_TYPE_POSTGRES = "pg";
    public static String NO_PORT = "-1";

    protected String getStoreFilename(String flag) {
        if(flag == null){
            flag = STORE_TYPE_DERBY_FILE; //sets default
        }
        switch (flag) {
            case STORE_TYPE_MYSQL:
                return "mysql.xml";
            case STORE_TYPE_FILE_STORE:
                return "fileStore.xml";
            case STORE_TYPE_MARIA_DB:
                return "mariadb.xml";
            case STORE_TYPE_POSTGRES:
                return "postgres.xml";
            case STORE_TYPE_DERBY_FILE:
            default:
                return "derby_fs.xml";
        }
    }

    @Override
    protected Map<String, String> setupTemplates() throws IOException {
        super.setupTemplates();
        // Only process templates if there is a reason to. 
        if (!(getArgMap().isInstall() || getArgMap().isUpgrade() || getArgMap().isRemove())) {
            return getTemplates();
        }
        getTemplates().put("${OA4MP_HOME}", getRoot().getCanonicalPath() + File.separator);
        String h = getHost();
        if (hasPort()) {
            h = h + ":" + getPort();
        }

        getTemplates().put("${JWT_KEY_ID}", getID(12));
        getTemplates().put("${DERBY_PASSWORD}", getSecret(8));
        getTemplates().put("${DERBY_BOOT_PASSWORD}", getSecret(8));

        getTemplates().put("${OA4MP_HOST}", h);
        InputStream is = getClass().getResourceAsStream("/tiles/" + getStoreFilename(getArgMap().getString(STORE_FLAG)));
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        copyStream(is, baos);
        String store = new String(baos.toString(StandardCharsets.UTF_8));
        is.close();
        // Now for a little trickery. Run the templates on the store
        store = doReplace(store);
        if (StringUtils.isTrivial(store)) {
            throw new NFWException("missing tiles for store \"" + getArgMap().getString(STORE_FLAG) + "\"");
        }
        getTemplates().put("${STORE}", store);
        return getTemplates();
    }

    SecureRandom secureRandom = new SecureRandom();

    protected String getSecret(int length) {
        byte[] ba = new byte[length];
        secureRandom.nextBytes(ba);
        return Base64.encodeBase64URLSafeString(ba);
    }

    protected String getID(int length) {
        byte[] ba = new byte[length];
        secureRandom.nextBytes(ba);
        BigInteger bi = new BigInteger(ba);
        return bi.toString(16).toUpperCase();
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
                case STORE_FLAG:
                    getArgMap().put(STORE_FLAG, args[++i]);
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
        say(STORE_FLAG + " = the storage for this service. You may use one of");
        say(StringUtils.RJustify(STORE_TYPE_DERBY_FILE, 20) + " = (default) use an auto-configured Derby database locally");
        say(StringUtils.RJustify(STORE_TYPE_MYSQL, 20) + " = use your MySQL database.");
        say(StringUtils.RJustify(STORE_TYPE_MARIA_DB, 20) + " = use your MariaDB database.");
        say(StringUtils.RJustify(STORE_TYPE_POSTGRES, 20) + " = use your PostgreSQL database.");
        say(StringUtils.RJustify(STORE_TYPE_FILE_STORE, 20) + " = use a file store. (only for testing, really)");
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
    protected String getSetup() {
        return "/oa4mp/setup.yaml";
    }

}
