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
    public static final int DEFAULT_BATCH_SIZE = 500;

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
        getMigrater().migrateAll(targetSE, isNoTransactions(), getBatchSize(), isUpkeepOn(), isPacerOn());

        say("TOTAL Processing time for all operations:" + StringUtils.formatElapsedTime(System.currentTimeMillis() - now));
    }


    @Override
    public void help() {

    }

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

    protected void loadEnvironments() {

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
                    if (dcp.getConnectionParameters().isCreateOne()) {
                        dcp.createStore();
                    }
                }
            }
        } catch (Throwable e) {
            e.printStackTrace();
            say("Could not load migration creation");
            return;
        }
        if (!(sourceSE.getClientStore() instanceof FileStore)) {
            say("the source client store is not a file store, but a" + sourceSE.getClientStore().getClass().getSimpleName());
            return;
        }
        FileStore clientStore = (FileStore) sourceSE.getClientStore();
        File dbDir = new File(clientStore.getStorageDirectory().getParentFile().getParentFile(), "migrate");

        DerbyConnectionPoolProvider derbyConnectionPoolProvider = DerbyConnectionPoolProvider.newInstance().
                setStoreType(DERBY_STORE_TYPE_FILE).
                setRootDirectory(clientStore.getStorageDirectory().getParentFile().getParent()).
                setDatabase(dbDir.getAbsolutePath());
        DerbyConnectionPool pool = (DerbyConnectionPool) derbyConnectionPoolProvider.get();
        sayv(getClass().getSimpleName() + " database file=" + pool.getConnectionParameters().getDatabaseName());
        if (!dbDir.exists()) {
            // Set up the migration database. This will create it if it does not exist.
            try {
                InputStream inputStream = getClass().getClassLoader().getResourceAsStream("derby-migrate.sql");
                createScript = SQLStore.crappySQLParser(FileUtil.readFileAsLines(inputStream));
                pool.setCreateScript(createScript);
                sayv("   creating migration database");
                pool.createStore();
                sayv("   done!");
                sayv("connect '" + pool.getConnectionParameters().getJdbcUrl() + "';");
                doIngest = true;
            } catch (Throwable t) {
                t.printStackTrace();
                say("could not create migration store \"" + dbDir.getAbsolutePath() + "\":" + t.getMessage());
                return;
            }
        }

        MigrateKeys migrateKeys = new MigrateKeys();
        MigrateTable migrateTable = new MigrateTable(migrateKeys, "oauth2", "", "migrate");
        MEProvider<MigrationEntry> meProvider = new MEProvider<MigrationEntry>();
        MigrationEntryConverter<MigrationEntry> converter = new MigrationEntryConverter<MigrationEntry>(migrateKeys, meProvider);
        migrateStore = new MigrateStore(pool, migrateTable, new MEProvider<MigrationEntry>(), converter);
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

    boolean upkeepOn = false;
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
    public static final String CONFIG_HELP = "--help";
    public static final String CONFIG_SETUP = "-setup";

    public static void showHelp() {
        int width = 20;
        String eq = " = ";
        String indent = "                       ";
        say(FSMigrationTool.class.getSimpleName() + ": a tool to migrate an existing filestore to another store");
        say("The scenario is that you have a possible enormous filestore with thousands of entries and need");
        say("to move the contents to a different type of OA4MP store. Such a migration should be done separately, ");
        say("not when the server is running since the load could be quite high. ");
        say(StringUtils.RJustify(CONFIG_BATCH_SIZE, 20) + eq + "  The number of files to process at once. Default is " + DEFAULT_BATCH_SIZE);
        say(StringUtils.RJustify(CONFIG_CLEANUP, 20) + eq + "removes the migration database. Overrides all other options!");
        say(StringUtils.RJustify(CONFIG_DO_UPKEEP, 20) + eq + "Applies upkeep in the target store to all entries on import.");
        say(StringUtils.RJustify(CONFIG_HELP, 20) + eq + "  show the help.");
        say(StringUtils.RJustify(CONFIG_NO_TRANSACTIONS, 20) + eq + "does not migrate any pending transfers. This means");
        say(indent + "any pending transfers are lost.");
        say(StringUtils.RJustify(CONFIG_PACE_OFF, 20) + eq + "disables the pacer (status bar thingy.)");
        say(StringUtils.RJustify(CONFIG_SOURCE_CFG, 20) + eq + "  the full path to the source config file.");
        say(StringUtils.RJustify(CONFIG_SETUP, 20) + eq + "  creates any required databases. Run this before anything else!.");
        say(StringUtils.RJustify(CONFIG_SOURCE_CFG_NAME, 20) + eq + "  the name of the configuration. Must be a file store.");
        say(StringUtils.RJustify(CONFIG_TARGET_CFG_NAME, 20) + eq + "  the full path to the configuration file.");
        say(indent + "If omitted, assumed to be the same as " + CONFIG_SOURCE_CFG);
        say(StringUtils.RJustify(CONFIG_TARGET_CFG_NAME, 20) + eq + "  the name of the target configuration");
        say(StringUtils.RJustify(CONFIG_VERBOSE, 20) + eq + "makes the operation much chattier");
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

    protected File getDBDir() {
        // This exists as a separate call mostly because my debugger attempts to load the entire
        // client configuration database to display it as a map -- test store had 800+k entries! and never completed
        // If this is in a separate call, that is avoided.
        ConfigurationNode node = XMLConfigUtil.findConfiguration(getSourceFile(), getSourceConfigName(), COMPONENT);
        OA2ConfigurationLoader sourceLoader = new OA2ConfigurationLoader<>(node);
        sourceSE = (OA2SE) sourceLoader.load();
        FileStore clientStore = (FileStore) sourceSE.getClientStore();
        return new File(clientStore.getStorageDirectory().getParentFile().getParentFile(), "migrate");
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
        setUpkeepOn(inputLine.hasArg(CONFIG_DO_UPKEEP));
        inputLine.removeSwitch(CONFIG_DO_UPKEEP);
        if (inputLine.hasArg(CONFIG_BATCH_SIZE)) {
            setBatchSize(inputLine.getNextIntArg(CONFIG_BATCH_SIZE));
            inputLine.removeSwitchAndValue(CONFIG_BATCH_SIZE);
        }

        return true;
    }

    public static void main(String[] args) throws Throwable {
        String[] v = new String[1 + args.length];
        v[0] = FSMigrationTool.class.getSimpleName();// need a dummy argument for input line
        System.arraycopy(args, 0, v, 1, args.length);
        InputLine inputLine = new InputLine(v);
        if (args.length == 0 || inputLine.hasArg(HELP_LONG_OPTION)) {
            showHelp();
            return;
        }
        FSMigrationTool fsm = new FSMigrationTool();
        fsm.doCleanup = inputLine.hasArg(CONFIG_CLEANUP);
        if (fsm.doCleanup) {
            fsm.removeMigrationDB(inputLine);  // this can also show help, do before showing general help
            return;
        }

        if (inputLine.hasArg(CONFIG_HELP)) {
            FSMigrationTool.showHelp();
            return;
        }
        if (!fsm.getArgs(inputLine)) {
            return;
        }
        fsm.loadEnvironments();
        fsm.doIt();
    }

}
