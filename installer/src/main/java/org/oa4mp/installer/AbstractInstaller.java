package org.oa4mp.installer;

import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.installer.WebInstaller;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;

/**
 * This centralizes the common code for the server and client installers. In particular, it allows
 * for getting tiles as resources and inserting them into a configuration.
 */
/*
  This entire module exists because we are trying to minimize the number of dependencies
  for both client and server installers, but need shared code.
 */
public abstract class AbstractInstaller extends WebInstaller {
    static protected final String STORE_FLAG = "-store";
    static protected final String STORE_TYPE_DERBY_FILE = "derby_file";
    static protected final String STORE_TYPE_FILE_STORE = "file_store";
    static protected final String STORE_TYPE_MYSQL = "mysql";
    static protected final String STORE_TYPE_MARIA_DB = "mariadb";
    static protected final String STORE_TYPE_POSTGRES = "pg";

    /**
     * The name of the resource directory with all of the tiles (snippets that will
     * be substituted) for the release. Typically it is called /tiles/.
     * @return
     */
    public  String getStoreTileDirectory(){
            return "/tiles/";
    }
    @Override
    protected String getSetup() {
        return "/oa4mp/setup.yaml";
    }
    protected String getStoreFilename(String flag) {
        if (flag == null) {
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
        getTemplates().put("${OA4MP_HOME}", getRoot().getCanonicalPath() + File.separator);

        getTemplates().put("${JWT_KEY_ID}", getID(12));
        getTemplates().put("${DERBY_PASSWORD}", getSecret(8));
        getTemplates().put("${DERBY_BOOT_PASSWORD}", getSecret(8));

        InputStream is = getClass().getResourceAsStream(getStoreTileDirectory() + getStoreFilename(getArgMap().getString(STORE_FLAG)));
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

    @Override
    protected void setupArgMap(String[] args) {
        super.setupArgMap(args);
        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case STORE_FLAG:
                    getArgMap().put(STORE_FLAG, args[++i]);
                    break;
            }
        }
    }

    @Override
    protected void printMoreArgHelp() throws IOException {
        super.printMoreArgHelp();
        say(STORE_FLAG + " = the storage for this service. You may use one of");
        say(StringUtils.RJustify(STORE_TYPE_DERBY_FILE, 20) + " = (default) use an auto-configured Derby database locally");
        say(StringUtils.RJustify(STORE_TYPE_MYSQL, 20) + " = use your MySQL database.");
        say(StringUtils.RJustify(STORE_TYPE_MARIA_DB, 20) + " = use your MariaDB database.");
        say(StringUtils.RJustify(STORE_TYPE_POSTGRES, 20) + " = use your PostgreSQL database.");
        say(StringUtils.RJustify(STORE_TYPE_FILE_STORE, 20) + " = use a file store. (only for testing, really)");
    }

}
