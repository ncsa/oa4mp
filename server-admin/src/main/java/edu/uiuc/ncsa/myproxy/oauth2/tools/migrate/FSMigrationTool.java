package edu.uiuc.ncsa.myproxy.oauth2.tools.migrate;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.loader.OA2ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.FileUtil;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPoolProvider;
import edu.uiuc.ncsa.security.util.cli.CLITool;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.configuration.XMLConfigUtil;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags.COMPONENT;
import static edu.uiuc.ncsa.security.core.configuration.StorageConfigurationTags.DERBY_STORE_TYPE_FILE;

/**
 * Migration tool for old style file stores to (at this point) a Derby store.
 * This loads or creates stores needed and then runs the {@link FSMigrater}
 * The issue is that a lot of installs have been using file stores which have
 * become immense -- hundreds of thousands of auto-registered clients -- most
 * of which are one-time use or similar. The Upkeep facility cannot stay ahead
 * of this since the assumption with the store initially was pretty small sized.
 * The solution is to have an actual migration tool that will read the entire
 * source store and batch it up a target store.
 * <p>Created by Jeff Gaynor<br>
 * on 2/24/24 at  7:09 AM
 */
/*
   This works by reading through everything in the FS store directory and creating
   a master database list of what to import, then making a pass in batches
   to do the work. Note that this is aimed at large file stores -- tens if not
   hundreds of thousands of entries -- which are causing routine operations to
   crash in OA4MP, Administrators therefore need a special tool to do the import
   that takes this into account.
 */
public class FSMigrationTool extends CLITool {
    public static final int DEFAULT_BATCH_SIZE = 15000;

    @Override
    public String getComponentName() {
        return null;
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() throws Exception {
        return null;
    }

    public FSMigrater getMigrater() {
        if (migrater == null) {
            migrater = new FSMigrater(migrateStore);
        }
        return migrater;
    }

    public void setMigrater(FSMigrater migrater) {
        this.migrater = migrater;
    }

    FSMigrater migrater = null;

    @Override
    public void doIt() throws Exception {
        long now = System.currentTimeMillis();
        if (doIngest) {
            // say("done with setting up databases. You may now run this ");
            //return;
            getMigrater().ingest(sourceSE, isNoTransactions(), getBatchSize(), isPacerOn());
        }
        if(storeName == null){
            getMigrater().migrateAll(targetSE, isNoTransactions(), getBatchSize(), isUpkeepOn(), isPacerOn());
        } else {
            getMigrater().migrate(targetSE, getBatchSize(), isUpkeepOn(), storeName, isPacerOn());
        }

        say("TOTAL Processing time for all operations:" + StringUtils.formatElapsedTime(System.currentTimeMillis() - now));
    }


    @Override
    public void help() {

    }
    String storeName = null;
    OA2SE sourceSE;
    OA2SE targetSE;
    MigrateStore migrateStore;

    public void setSourceFile(String sourceFile) {
        this.sourceFile = sourceFile;
    }

    public void setTargetFile(String targetFile) {
        this.targetFile = targetFile;
    }

    public void setSourceConfigName(String sourceConfigName) {
        this.sourceConfigName = sourceConfigName;
    }

    public void setTargetConfigName(String targetConfigName) {
        this.targetConfigName = targetConfigName;
    }

    @Override
    public void setVerbose(boolean verbose) {
        isVerbose = verbose;
    }

    public void setBatchSize(int batchSize) {
        this.batchSize = batchSize;
    }

    int batchSize = DEFAULT_BATCH_SIZE;

    public boolean isPacerOn() {
        return pacerOn;
    }

    public void setPacerOn(boolean pacerOn) {
        this.pacerOn = pacerOn;
    }

    boolean pacerOn = true;

    public void setNoTransactions(boolean noTransactions) {
        this.noTransactions = noTransactions;
    }

    String sourceFile;
    String targetFile;
    String sourceConfigName;

    public OA2SE getSourceSE() {
        return sourceSE;
    }

    public OA2SE getTargetSE() {
        return targetSE;
    }

    public String getSourceFile() {
        return sourceFile;
    }

    public String getTargetFile() {
        return targetFile;
    }

    public String getSourceConfigName() {
        return sourceConfigName;
    }

    public String getTargetConfigName() {
        return targetConfigName;
    }

    @Override
    public boolean isVerbose() {
        return isVerbose;
    }

    public int getBatchSize() {
        return batchSize;
    }

    String targetConfigName;
    public static String INGESTION_FILE_NAME = "ingest";

    /**
     * Loads the environment. This returns true if the operation succeeded.
     *
     * @return
     */
    protected boolean loadEnvironments() {

        List<String> createScript = null;
        try {
            ConfigurationNode node = XMLConfigUtil.findConfiguration(getSourceFile(), getSourceConfigName(), COMPONENT);
            OA2ConfigurationLoader sourceLoader = new OA2ConfigurationLoader<>(node);
            sourceSE = (OA2SE) sourceLoader.load();

            node = XMLConfigUtil.findConfiguration(getTargetFile(), getTargetConfigName(), COMPONENT);
            OA2ConfigurationLoader targetLoader = new OA2ConfigurationLoader<>(node);
            targetSE = (OA2SE) targetLoader.load();

            if (targetSE.getClientStore() instanceof SQLStore) {
                if (((SQLStore) targetSE.getClientStore()).getConnectionPool() instanceof DerbyConnectionPool) {
                    DerbyConnectionPool dcp = (DerbyConnectionPool) ((SQLStore) targetSE.getClientStore()).getConnectionPool();
                    if (showConnect) {
                        say("target database connection string:");
                        say("  " + dcp.getConnectionParameters().getDerbyConnectionString());
                    }
                    if (dcp.getConnectionParameters().isCreateOne()) {
                        say("creating target store");
                        dcp.createStore();
                        say("...done!");
                        if (setup) {
                            say("...exiting.");
                            return false;
                        }
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
            say("Could not load migration creation");
            return false;
        }
        if (!(sourceSE.getClientStore() instanceof FileStore)) {
            say("the source client store is not a file store, but a" + sourceSE.getClientStore().getClass().getSimpleName());
            return false;
        }
        FileStore clientStore = (FileStore) sourceSE.getClientStore();
        File dbDir = new File(clientStore.getStorageDirectory().getParentFile().getParentFile(), INGESTION_FILE_NAME);

        DerbyConnectionPoolProvider derbyConnectionPoolProvider = DerbyConnectionPoolProvider.newInstance().
                setStoreType(DERBY_STORE_TYPE_FILE).
                setRootDirectory(clientStore.getStorageDirectory().getParentFile().getParent()).
                setDatabase(dbDir.getAbsolutePath());
        DerbyConnectionPool pool = (DerbyConnectionPool) derbyConnectionPoolProvider.get();
        if (showConnect) {
            say("ingestion database connection string:");
            say("  " + pool.getConnectionParameters().getDerbyConnectionString());
        }
        if (dbDir.exists()) {
            sayv("ingestion database exists");
        } else {
            say("ingestion database not found");
            // Set up the ingestion database. This will create it if it does not exist.
            try {
                InputStream inputStream = getClass().getClassLoader().getResourceAsStream("derby-migrate.sql");
                createScript = SQLStore.crappySQLParser(FileUtil.readFileAsLines(inputStream));
                pool.setCreateScript(createScript);
                say("creating ingestion database");
                pool.createStore();
                say("...done!");

                doIngest = true;
            } catch (Throwable t) {
                t.printStackTrace();
                say("could not create ingestion store \"" + dbDir.getAbsolutePath() + "\":" + t.getMessage());
                return false;
            }
        }

        MigrateKeys migrateKeys = new MigrateKeys();
        MigrateTable migrateTable = new MigrateTable(migrateKeys, "oauth2", "", INGESTION_FILE_NAME);
        MEProvider<MigrationEntry> meProvider = new MEProvider<MigrationEntry>();
        MigrationEntryConverter<MigrationEntry> converter = new MigrationEntryConverter<MigrationEntry>(migrateKeys, meProvider);
        migrateStore = new MigrateStore(pool, migrateTable, new MEProvider<MigrationEntry>(), converter);
        if (resetIngestDB) {
            try {
                sayv("resetting ingest DB...");
              int updateCount =   migrateStore.resetImportCodes(storeName);
                sayv("...done! Update " + updateCount + " records.");

            } catch (Throwable t) {
                if (isVerbose) {
                    t.printStackTrace();
                }
                return false;
            }
        }
        return true;
    }

    boolean doIngest = false;
    boolean isVerbose = false;
//    connect 'jdbc:derby:/home/ncsa/temp/oa4mp2/fileStore/migrate;dataEncryption=true;user=oa4mp;bootPassword=Qwertyuiop321;password=Asdfghjkl123';

    protected void vsay(String x) {
        if (isVerbose) {
            say(x);
        }
    }


    public MigrateStore getMigrateStore() {
        return migrateStore;
    }

    public void setMigrateStore(MigrateStore migrateStore) {
        this.migrateStore = migrateStore;
    }

    public boolean isUpkeepOn() {
        return upkeepOn;
    }

    public void setUpkeepOn(boolean upkeepOn) {
        this.upkeepOn = upkeepOn;
    }

    boolean upkeepOn = true;
    public static final String CONFIG_SOURCE_CFG = "-src";
    public static final String CONFIG_TARGET_CFG = "-target";
    public static final String CONFIG_TARGET_CFG_NAME = "-targetName";
    public static final String CONFIG_SOURCE_CFG_NAME = "-srcName";
    public static final String CONFIG_BATCH_SIZE = "-batchSize";
    public static final String CONFIG_NO_TRANSACTIONS = "-noTransactions";
    public static final String CONFIG_DO_UPKEEP = "-upkeepOn";
    public static final String CONFIG_VERBOSE = "-v";
    public static final String CONFIG_PACE_OFF = "-noPacer";
    public static final String CONFIG_CLEANUP = "-cleanup";
    public static final String CONFIG_SHOW_CONNECT = "-showConnect";
    public static final String CONFIG_HELP = "--help";
    public static final String CONFIG_SETUP = "-setup";
    public static final String CONFIG_RESET = "-reset";
    public static final String CONFIG_STORE_NAME = "-storeName";

    public static void showHelp() {
        int width = 20;
        String eq = " : ";
        String indent = StringUtils.getBlanks(width + 1+2*eq.length());
        say(FSMigrationTool.class.getSimpleName() + ": a tool to migrate an existing filestore to another store");
        say("The scenario is that you have a possible enormous filestore with thousands of entries and need");
        say("to move the contents to a different type of OA4MP store. Such a migration should be done separately, ");
        say("not when the server is running since the load could be quite high. ");
        say("Type key: I = integer, F = flag (no arg), B = boolean (true | false), S = string");
        say("");
        say(StringUtils.RJustify("     Flag     ",20) + eq + "T" + eq + "                           Description");
        say(StringUtils.RJustify(CONFIG_BATCH_SIZE, 20) + eq + "I" + eq +"The number of files to process at once. Default is no batching.");
        say(StringUtils.RJustify(CONFIG_CLEANUP, 20) + eq + "F" + eq + "Removes the ingestion database. This will be executed, then the application will exit.");
        say(indent + "Since Derby does not have a nice way to clean databases up, it is included as a utility.");
        say(StringUtils.RJustify(CONFIG_HELP, 20) + eq + "F" + eq + "Show the help. Overrides all other flags. Note double hypen!");
        say(StringUtils.RJustify(CONFIG_NO_TRANSACTIONS, 20) + eq + "F" + eq + "Does not migrate any pending transfers. This means");
        say(indent + "any pending transfers are lost. Default is false.");
        say(StringUtils.RJustify(CONFIG_PACE_OFF, 20) + eq + "B" + eq +"Disables the pacer (status bar thingy.) default is true");
        say(StringUtils.RJustify(CONFIG_RESET, 20) + eq + "F" + eq + "If the ingest table exists, reset all of the entries to being un-imported.");
        say(indent + "This is useful if the import failed and you want to restart all over without re-ingesting");
        say(indent + "Note that this may be used with " + CONFIG_STORE_NAME + " to do a single component.");
        say(StringUtils.RJustify(CONFIG_SETUP, 20) + eq + "F" + eq +"Creates any required databases. This creates any databases then exits.");
        say(indent+"If omitted, the databases are created as needed and the migration is done.");
        say(StringUtils.RJustify(CONFIG_SHOW_CONNECT, 20) + eq + "F" + eq +"Show the Derby connection strings. Useful if you have Derby installed. Default is not to show.");
        say(StringUtils.RJustify(CONFIG_SOURCE_CFG, 20) + eq + "S" + eq + "The full path to the source config file.");
        say(StringUtils.RJustify(CONFIG_SOURCE_CFG_NAME, 20) + eq + "S" + eq +"The name of the configuration. Must be a file store.");
        say(StringUtils.RJustify(CONFIG_STORE_NAME, 20) + eq + "S" + eq + "The name of a single store component (these are the tag names in the XML");
        say(indent + "file). If you supply this, exactly that one component will be imported and nothing else. Used in conjuntion with");
        say(indent + CONFIG_RESET + ", resets only that named components.");
        say(StringUtils.RJustify(CONFIG_TARGET_CFG, 20) + eq + "S" +eq + "The full path to the configuration file.");
        say(indent + "If omitted, assumed to be the same as " + CONFIG_SOURCE_CFG);
        say(StringUtils.RJustify(CONFIG_TARGET_CFG_NAME, 20) + eq + "F"+eq +"The name of the target configuration");
        say(StringUtils.RJustify(CONFIG_DO_UPKEEP, 20) + eq + "B" + eq + "Applies upkeep in the target store to all entries on import. Default is true");
        say(StringUtils.RJustify(CONFIG_VERBOSE, 20) + eq + "F" + eq +"Makes the operation much chattier. Default is none.");
    }



    public boolean isNoTransactions() {
        return noTransactions;
    }

    boolean setup = false;
    boolean noTransactions = false;
    boolean doCleanup = false;

    protected void removeMigrationDB(InputLine inputLine) {
        if (inputLine.hasArg(CONFIG_HELP)) {
            say("The migration database is created in the source storage directory");
            say("and is a Derby database. This facility will remove one completely.");
            say("Note that this runs in stages, in that the migration database is created");
            say("and contains all of the information to import the source to the target.");
            say("In this way, if the actual import is interrupted, it can simply resume.");
            say("Also, if for some reason the ingestion is interrupted so that the migration ");
            say("database is incomplete, run this method and restart the whole process.");
            say("This is done in stages since some file stores have gotten immense and");
            say("migrating them is a very serious task that must be done carefully and");
            say("atomically.");
            return;
        }

        if (inputLine.hasArg(CONFIG_SOURCE_CFG)) {
            setSourceFile(inputLine.getNextArgFor(CONFIG_SOURCE_CFG));
            inputLine.removeSwitchAndValue(CONFIG_SOURCE_CFG);
        } else {
            say("missing " + CONFIG_SOURCE_CFG + " parameter.");
            return;
        }
        if (inputLine.hasArg(CONFIG_SOURCE_CFG_NAME)) {
            setSourceConfigName(inputLine.getNextArgFor(CONFIG_SOURCE_CFG_NAME));
            inputLine.removeSwitchAndValue(CONFIG_SOURCE_CFG_NAME);
        } else {
            say("missing " + CONFIG_SOURCE_CFG_NAME + " parameter.");
        }
        if(inputLine.hasArg(CONFIG_STORE_NAME)){
            storeName = inputLine.getNextArgFor(CONFIG_STORE_NAME).toLowerCase();
            inputLine.removeSwitchAndValue(CONFIG_STORE_NAME);
        }
        File dbDir = getDBDir();

        if (!dbDir.exists()) {
            say("no database found to remove at \"" + dbDir.getAbsolutePath() + "\"");
            return;
        }
        say("Remove the migration database at \"" + dbDir.getAbsolutePath() + "\"? (Y/n)");
        String inString = null;
        try {
            inString = readline();
        } catch (IOException e) {
            say("Sorry, that didn't work:" + e.getMessage());
            return;
        }
        if (!inString.equals("Y")) {
            say("aborting...");
            return;
        }
        nukeDir(dbDir);
        say("done");
    }

    boolean resetIngestDB = false;

    protected File getDBDir() {
        // This exists as a separate call mostly because my debugger attempts to load the entire
        // client configuration database to display it as a map -- test store had 800+k entries! and never completed
        // If this is in a separate call, that is avoided.
        ConfigurationNode node = XMLConfigUtil.findConfiguration(getSourceFile(), getSourceConfigName(), COMPONENT);
        OA2ConfigurationLoader sourceLoader = new OA2ConfigurationLoader<>(node);
        sourceSE = (OA2SE) sourceLoader.load();
        FileStore clientStore = (FileStore) sourceSE.getClientStore();
        return new File(clientStore.getStorageDirectory().getParentFile().getParentFile(), INGESTION_FILE_NAME);
    }

    /**
     * Removes <b><i>EVERYTHING</i></b> in the directory, <b><i>AND</i></b> the directory itself.
     *
     * @param dir
     */
    protected void nukeDir(File dir) {
        if (!dir.exists() || !dir.isDirectory()) {
            return;
        }
        File[] files = dir.listFiles();
        for (File file : files) {
            if (file.isDirectory()) {
                nukeDir(file);
            } else {
                file.delete();
            }
        }
        dir.delete();
    }

    protected boolean getArgs(InputLine inputLine) {
        if (inputLine.hasArg(CONFIG_VERBOSE)) {
            setVerbose(true);
            inputLine.removeSwitch(CONFIG_VERBOSE);
        }
        resetIngestDB = inputLine.hasArg(CONFIG_RESET);
        inputLine.removeSwitch(CONFIG_RESET);
        if (inputLine.hasArg(CONFIG_SOURCE_CFG)) {
            setSourceFile(inputLine.getNextArgFor(CONFIG_SOURCE_CFG));
            inputLine.removeSwitchAndValue(CONFIG_SOURCE_CFG);
        } else {
            say("missing " + CONFIG_SOURCE_CFG + " parameter.");
            return false;
        }

        setup = inputLine.hasArg(CONFIG_SETUP);
        inputLine.removeSwitch(CONFIG_SETUP);
        if (inputLine.hasArg(CONFIG_TARGET_CFG)) {
            setTargetFile(inputLine.getNextArgFor(CONFIG_TARGET_CFG));
            inputLine.removeSwitchAndValue(CONFIG_TARGET_CFG);
        } else {
            setTargetFile(getSourceFile());
            sayv("No explicit target configuration, using the source configuration for both.");
        }


        if (inputLine.hasArg(CONFIG_SOURCE_CFG_NAME)) {
            setSourceConfigName(inputLine.getNextArgFor(CONFIG_SOURCE_CFG_NAME));
            inputLine.removeSwitchAndValue(CONFIG_SOURCE_CFG_NAME);
        } else {
            say("missing " + CONFIG_SOURCE_CFG_NAME + " parameter.");
            return false;
        }
        if (inputLine.hasArg(CONFIG_TARGET_CFG_NAME)) {
            setTargetConfigName(inputLine.getNextArgFor(CONFIG_TARGET_CFG_NAME));
            inputLine.removeSwitchAndValue(CONFIG_TARGET_CFG_NAME);
        } else {
            say("missing " + CONFIG_TARGET_CFG_NAME + " parameter.");
            return false;
        }
        setNoTransactions(inputLine.hasArg(CONFIG_NO_TRANSACTIONS));
        inputLine.removeSwitch(CONFIG_NO_TRANSACTIONS);
        setPacerOn(!inputLine.hasArg(CONFIG_PACE_OFF));
        inputLine.removeSwitch(CONFIG_PACE_OFF);
        if (inputLine.hasArg(CONFIG_DO_UPKEEP)) {
            setUpkeepOn("true".equalsIgnoreCase(inputLine.getNextArgFor(CONFIG_DO_UPKEEP)));
            inputLine.removeSwitch(CONFIG_DO_UPKEEP);
        }
        if (inputLine.hasArg(CONFIG_BATCH_SIZE)) {
            setBatchSize(inputLine.getNextIntArg(CONFIG_BATCH_SIZE));
            inputLine.removeSwitchAndValue(CONFIG_BATCH_SIZE);
        }

        return true;
    }

    boolean showConnect = false;

    public static void main(String[] args) throws Throwable {
        String[] v = new String[1 + args.length];
        v[0] = FSMigrationTool.class.getSimpleName();// need a dummy argument for input line
        System.arraycopy(args, 0, v, 1, args.length);
        InputLine inputLine = new InputLine(v);
        if (args.length == 0 || inputLine.hasArg(CONFIG_HELP)) {
            showHelp();
            return;
        }
        FSMigrationTool fsm = new FSMigrationTool();
        // Do the cleanup as a separate task and exit.
        fsm.doCleanup = inputLine.hasArg(CONFIG_CLEANUP);
        fsm.showConnect = inputLine.hasArg(CONFIG_SHOW_CONNECT);
        inputLine.removeSwitch(CONFIG_SHOW_CONNECT);

        if (fsm.doCleanup) {
            fsm.removeMigrationDB(inputLine);  // this can also show help, do before showing general help
            return;
        }


        if (!fsm.getArgs(inputLine)) {
            return;
        }
        if (fsm.loadEnvironments()) { // returns true
            fsm.doIt();
        }
    }

}
