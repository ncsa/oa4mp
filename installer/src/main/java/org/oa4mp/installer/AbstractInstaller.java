package org.oa4mp.installer;

import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.FileUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.installer.WebInstaller;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPoolProvider;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import static edu.uiuc.ncsa.security.core.configuration.StorageConfigurationTags.DERBY_STORE_TYPE_FILE;

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
    static protected final String STORE_TYPE_DERBY = "derby";
    static protected final String STORE_TYPE_FILE_STORE = "file_store";
    static protected final String STORE_TYPE_MYSQL = "mysql";
    static protected final String STORE_TYPE_MARIA_DB = "mariadb";
    static protected final String STORE_TYPE_POSTGRES = "pg";

    /**
     * The name of the resource directory with all of the tiles (snippets that will
     * be substituted) for the release. Typically it is called /tiles/.
     *
     * @return
     */
    public String getStoreTileDirectory() {
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
            case STORE_TYPE_DERBY:
                return "derby.xml";
            case STORE_TYPE_DERBY_FILE:
            default:
                return "derby_fs.xml";
        }
    }

    protected void setupDerbyFS() throws Throwable {
        String dbDir = getRoot().getAbsolutePath() + "/var/storage/derby";
        DerbyConnectionPoolProvider derbyConnectionPoolProvider = DerbyConnectionPoolProvider.newInstance().
                setStoreType(DERBY_STORE_TYPE_FILE).
                setRootDirectory(dbDir).
                setSchema("oa4mp").
                setDatabase(dbDir + "/oa4mp").
                setBootPassword(getTemplates().get("${DERBY_BOOT_PASSWORD}")).
                setPassword(getTemplates().get("${DERBY_PASSWORD}")).
                setUsername(getTemplates().get("${DERBY_USERNAME}")
                );
        DerbyConnectionPool pool = (DerbyConnectionPool) derbyConnectionPoolProvider.get();
        pool.getConnectionParameters().setCreateOne(true);
        // need to get the create script as a list of strings.
        // should be in ${OA4MP_HOME}etc/oa4mp-derby.sql
        List<String> script = FileUtil.readFileAsLines(getDerbySetupScriptPath());
        //List<String> script = FileUtil.readFileAsLines(getTemplates().get("${OA4MP_HOME}") + "etc/oa4mp-derby.sql");
        script = SQLStore.crappySQLParser(script);

        pool.setCreateScript(script);
        pool.createStore();
        trace("JDBC connection URL:\n\t" + pool.getConnectionParameters().getJdbcUrl());
    }

    protected abstract String getDerbySetupScriptPath();

    @Override
    protected Map<String, String> setupTemplates() throws IOException {
        super.setupTemplates();
        // Only process templates if there is a reason to.
        getTemplates().put("${OA4MP_HOME}", getRoot().getCanonicalPath() + File.separator);

        getTemplates().put("${JWT_KEY_ID}", getID(12));
        getTemplates().put("${DERBY_USERNAME}", "oa4mp");
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
        if(!getArgMap().containsKey(STORE_FLAG)) {
            getArgMap().put(STORE_FLAG, STORE_TYPE_DERBY_FILE);
        }
    }

    @Override
    protected void printMoreArgHelp() throws IOException {
        super.printMoreArgHelp();
        say(STORE_FLAG + " = the storage for this service. You may use one of");
        say(StringUtils.RJustify(STORE_TYPE_DERBY_FILE, 20) + " = (default) use an auto-configured Derby database locally");
        say(StringUtils.RJustify(STORE_TYPE_DERBY, 20) + " = use yor derby server. ");
        say(StringUtils.RJustify(STORE_TYPE_MYSQL, 20) + " = use your MySQL database.");
        say(StringUtils.RJustify(STORE_TYPE_MARIA_DB, 20) + " = use your MariaDB database.");
        say(StringUtils.RJustify(STORE_TYPE_POSTGRES, 20) + " = use your PostgreSQL database.");
        say(StringUtils.RJustify(STORE_TYPE_FILE_STORE, 20) + " = use a file store. (only for testing, really)");
    }

    @Override
    protected void doInstallOrUpdate(boolean isUpdate) throws Throwable {
        super.doInstallOrUpdate(isUpdate);
        if (!isUpdate) {
            // do Derby file store install if needed
            if (getArgMap().getString(STORE_FLAG).equals(STORE_TYPE_DERBY_FILE)) {
                setupDerbyFS();
            }

        }
    }
}
