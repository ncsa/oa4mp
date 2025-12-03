package org.oa4mp.server.admin.oauth2.tools.migrate;

import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.cf.CFXMLConfigurations;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.core.util.FileUtil;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPoolProvider;
import edu.uiuc.ncsa.security.util.cli.CLITool2;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;

import java.io.*;
import java.lang.reflect.Field;
import java.util.*;

import static edu.uiuc.ncsa.security.core.configuration.StorageConfigurationTags.DERBY_STORE_TYPE_FILE;
import static edu.uiuc.ncsa.security.core.util.StringUtils.*;
import static org.oa4mp.server.api.OA4MPConfigTags.COMPONENT;

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
public class FSMigrationTool extends CLITool2 {
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
            migrater = new FSMigrater(migrateStore, echoWriter);
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
            getMigrater().ingest(sourceSE, isNoTransactions(), getBatchSize(), isPacerOn());
        }
        if (storeName == null) {
            getMigrater().migrateAll(targetSE, isNoTransactions(), getBatchSize(), isUpkeepOn(), isPacerOn());
        } else {
            getMigrater().migrate(targetSE, getBatchSize(), isUpkeepOn(), storeName, isPacerOn());
        }

        say("TOTAL Processing time for all operations:" + formatElapsedTime(System.currentTimeMillis() - now));

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
            CFNode node =CFXMLConfigurations.findConfiguration(getSourceFile(), COMPONENT, getSourceConfigName());
            OA2CFConfigurationLoader sourceLoader = new OA2CFConfigurationLoader<>(node);
            sourceSE = (OA2SE) sourceLoader.load();

            node = CFXMLConfigurations.findConfiguration(getTargetFile(),COMPONENT,  getTargetConfigName());
            OA2CFConfigurationLoader targetLoader = new OA2CFConfigurationLoader<>(node);
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
                int updateCount = migrateStore.resetImportCodes(storeName);
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
    public static final String CONFIG_ECHO_FILE = "-echoFile";
    public static final String CONFIG_ECHO_APPEND = "-echoAppend";

    String echoFileName = null;
    static Writer echoWriter = null;

    public static void say(String x) {
        //    System.out.println(x);
        getIoInterface().println(x);
        if (echoOn()) {
            try {

                echoWriter.write(x + "\n");
            } catch (IOException e) {
                echoWriter = null; // disables it.
                getIoInterface().println("warning: echoing failed. echo is disabled:" + e.getMessage());
            }
        }
    }

    protected static boolean echoOn() {
        return echoWriter != null;
    }

    protected static Map<String, HelpEntry> helpMap = null;

    protected static class HelpEntry {
        public HelpEntry(String name, String type, String defaultValue, String description) {
            this.name = name;
            this.type = type;
            this.description = description;
            this.defaultValue = defaultValue;
        }

        String name;
        String type;
        String description;
        String[] description2;
        String defaultValue="-";
    }

    /**
     * Creates the help map. This adds the entry by key. Later these are alphabetized, formatted, etc.
     *
     * @return
     */
    protected static Map<String, HelpEntry> getHelpMap() {
        if (helpMap == null) {
            helpMap = new HashMap<>();
            addHelpEntry(CONFIG_BATCH_SIZE, "I", "0", "The number of files to process at once. Default (0) is no batching.");
            addHelpEntry(CONFIG_CLEANUP, "F", "-", "Removes the ingestion database. This will be executed, then the application will exit.",
                    new String[]{"Since Derby does not have a nice way to clean databases up, it is included as a utility."});
            addHelpEntry(CONFIG_ECHO_APPEND, "B", "true", "If echoing, append to the echo file. Default is true. If false, the file is overwritten.");
            addHelpEntry(CONFIG_ECHO_FILE, "S", "Path to a file (always overwritten) that echos the console output.");
            addHelpEntry(CONFIG_HELP, "F", "Show the help. Overrides all other flags. Note double hypen!");
            addHelpEntry(CONFIG_NO_TRANSACTIONS, "F", "Does not migrate any pending transfers. This means",
                    new String[]{"any pending transfers are lost. Default is false."});
            addHelpEntry(CONFIG_PACE_OFF, "B", "true", "Disables the pacer (status bar thingy.) default is true");
            addHelpEntry(CONFIG_RESET, "F", "If the ingest table exists, reset all of the entries to being un-imported.",
                    new String[]{"This is useful if the import failed and you want to restart all over without re-ingesting",
                            "Note that this may be used with " + CONFIG_STORE_NAME + " to do a single component."});
            addHelpEntry(CONFIG_SETUP, "F", "Creates any required databases. This creates any databases then exits.",
                    new String[]{"If omitted, the databases are created as needed and the migration is done."});
            addHelpEntry(CONFIG_SHOW_CONNECT, "F", "false","Show the Derby connection strings. Useful if you have Derby installed. Default is not to show.");
            addHelpEntry(CONFIG_SOURCE_CFG, "S", "The full path to the source config file.");
            addHelpEntry(CONFIG_SOURCE_CFG_NAME, "S", "The name of the configuration. Must be a file store.");
            addHelpEntry(CONFIG_STORE_NAME, "S", "The name of a single store component (these are the tag names in the XML",
                    new String[]{"file). If you supply this, exactly that one component will be imported and nothing else.",
                            "Used in conjuntion with " + CONFIG_RESET + ", resets only that named components."});
            addHelpEntry(CONFIG_TARGET_CFG, "S", "The full path to the configuration file.",
                    new String[]{"If omitted, assumed to be the same as " + CONFIG_SOURCE_CFG});
            addHelpEntry(CONFIG_TARGET_CFG_NAME, "F", "The name of the target configuration");
            addHelpEntry(CONFIG_DO_UPKEEP, "B", "true", "Applies upkeep in the target store to all entries on import. Default is true");
            addHelpEntry(CONFIG_VERBOSE, "F", "Makes the operation much chattier. Default is none.");
        }
        return helpMap;
    }

    protected static void addHelpEntry(String name, String type, String description) {
        addHelpEntry(name, type, "-", description, null);
    }

    protected static void addHelpEntry(String name, String type, String description,
                                       String[] description2) {
        addHelpEntry(name, type, "-", description, description2);
    }

    protected static void addHelpEntry(String name,
                                       String type,
                                       String defaultValue,
                                       String description) {
        addHelpEntry(name, type, defaultValue, description, null);
    }

    protected static void addHelpEntry(String name,
                                       String type,
                                       String defaultValue,
                                       String description,
                                       String[] description2) {
        HelpEntry helpEntry = new HelpEntry(name, type, defaultValue, description);
        if (description2 != null && 0 < description2.length) {
            helpEntry.description2 = description2;
        }
        helpMap.put(name, helpEntry);

    }

    public static void showHelp() throws IllegalAccessException {

        say(FSMigrationTool.class.getSimpleName() + ": a tool to migrate an existing filestore to another store");
        say("The scenario is that you have a possible enormous filestore with thousands of entries and need");
        say("to move the contents to a different type of OA4MP store. Such a migration should be done separately, ");
        say("not when the server is running since the load could be quite high. ");
        say("Type key: I = integer, F = flag (no arg), B = boolean (true | false), S = string");
        say("If there is a default value, given, otherwise there is a \"-\"");
        say("");

     //   oldHelp();
      //  say("=======================================");
        newHelp();
    }

    /**
     * This will take the help entries and format them. The {@link #oldHelp()}  was just getting to be a huge
     * mess to update.
     */
    private static void newHelp() throws IllegalAccessException {
        // next involve some introspection and setup. These only run once.
        getAllConfigNames();
        getHelpMap();
        int width = 0;
        for (String name : ALL_CONFIG_NAMES) {
            width = Math.max(width, name.length());
        }
        String spacer = "|";
        int typeWidth = 3; // how much space to leave for type
        int defaultWidth = 5; // how much space to leave for default.
        String indent =
                getBlanks(width +  typeWidth + defaultWidth + 3 * spacer.length()-1);
        String title = center("Name", width) + spacer +
                center("T", typeWidth) + spacer +
                center("Def", defaultWidth) + spacer +
                center("Description", 40);
        say(title);
        for (String configName : ALL_CONFIG_NAMES) {
            HelpEntry he = helpMap.get(configName);
            String line = RJustify(configName, width) + spacer + center(he.type, typeWidth) + spacer + center(he.defaultValue, defaultWidth) + spacer + " " + he.description;
            say(line);
            if(he.description2!=null){
                for(String d : he.description2){
                    say(indent + spacer + " " + d);
                }
            }
        }
        say("Column Key:");
        say("T = type, Def = default");
        say("Table entry key:");
        say("B = boolean, true or false");
        say("F = flag (present or not)");
        say("S = String. Double quote as needed");
        say("**************************************************************");
        say("* Be sure to read the documentation either on the website at *");
        say("*      https://oa4mp.org/pdf/filestore-migration.pdf         *");
        say("* or included in the standard distribution in                *");
        say("*      $OA4MP_SERVER/docs/filestore-migration.pdf            *");
        say("**************************************************************");
    }

    private static void oldHelp() {
        int width = 20;
        String eq = " : ";
        String indent = getBlanks(width + 1 + 2 * eq.length());
        say("Type key: I = integer, F = flag (no arg), B = boolean (true | false), S = string");
        say("");
        say(RJustify("     Flag     ", 20) + eq + "T" + eq + "                           Description");
        say(RJustify(CONFIG_BATCH_SIZE, 20) + eq + "I" + eq + "The number of files to process at once. Default is no batching.");
        say(RJustify(CONFIG_CLEANUP, 20) + eq + "F" + eq + "Removes the ingestion database. This will be executed, then the application will exit.");
        say(indent + "Since Derby does not have a nice way to clean databases up, it is included as a utility.");
        say(RJustify(CONFIG_ECHO_APPEND, 20) + eq + "B" + eq + "If echoing, append to the echo file. Default is true. If false, the file is overwritten.");
        say(RJustify(CONFIG_ECHO_FILE, 20) + eq + "S" + eq + "Path to a file (always overwritten) that echos the console output.");
        say(RJustify(CONFIG_HELP, 20) + eq + "F" + eq + "Show the help. Overrides all other flags. Note double hypen!");
        say(RJustify(CONFIG_NO_TRANSACTIONS, 20) + eq + "F" + eq + "Does not migrate any pending transfers. This means");
        say(indent + "any pending transfers are lost. Default is false.");
        say(RJustify(CONFIG_PACE_OFF, 20) + eq + "B" + eq + "Disables the pacer (status bar thingy.) default is true");
        say(RJustify(CONFIG_RESET, 20) + eq + "F" + eq + "If the ingest table exists, reset all of the entries to being un-imported.");
        say(indent + "This is useful if the import failed and you want to restart all over without re-ingesting");
        say(indent + "Note that this may be used with " + CONFIG_STORE_NAME + " to do a single component.");
        say(RJustify(CONFIG_SETUP, 20) + eq + "F" + eq + "Creates any required databases. This creates any databases then exits.");
        say(indent + "If omitted, the databases are created as needed and the migration is done.");
        say(RJustify(CONFIG_SHOW_CONNECT, 20) + eq + "F" + eq + "Show the Derby connection strings. Useful if you have Derby installed. Default is not to show.");
        say(RJustify(CONFIG_SOURCE_CFG, 20) + eq + "S" + eq + "The full path to the source config file.");
        say(RJustify(CONFIG_SOURCE_CFG_NAME, 20) + eq + "S" + eq + "The name of the configuration. Must be a file store.");
        say(RJustify(CONFIG_STORE_NAME, 20) + eq + "S" + eq + "The name of a single store component (these are the tag names in the XML");
        say(indent + "file). If you supply this, exactly that one component will be imported and nothing else. Used in conjuntion with");
        say(indent + CONFIG_RESET + ", resets only that named components.");
        say(RJustify(CONFIG_TARGET_CFG, 20) + eq + "S" + eq + "The full path to the configuration file.");
        say(indent + "If omitted, assumed to be the same as " + CONFIG_SOURCE_CFG);
        say(RJustify(CONFIG_TARGET_CFG_NAME, 20) + eq + "F" + eq + "The name of the target configuration");
        say(RJustify(CONFIG_DO_UPKEEP, 20) + eq + "B" + eq + "Applies upkeep in the target store to all entries on import. Default is true");
        say(RJustify(CONFIG_VERBOSE, 20) + eq + "F" + eq + "Makes the operation much chattier. Default is none.");
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
        if (inputLine.hasArg(CONFIG_STORE_NAME)) {
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
        CFNode node = CFXMLConfigurations.findConfiguration(getSourceFile(), getSourceConfigName(), COMPONENT);
        OA2CFConfigurationLoader sourceLoader = new OA2CFConfigurationLoader<>(node);
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

    protected boolean getArgs(InputLine inputLine) throws IOException {
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

        //if (setupEcho(inputLine)) return false;
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

    private void setupEcho(InputLine inputLine) throws IOException {
        if (inputLine.hasArg(CONFIG_ECHO_APPEND)) {
            setEchoAppend(inputLine.getNextArgFor(CONFIG_ECHO_APPEND).equals("true"));
            inputLine.removeSwitchAndValue(CONFIG_ECHO_APPEND);
        }

        if (inputLine.hasArg(CONFIG_ECHO_FILE)) {
            echoFileName = inputLine.getNextArgFor(CONFIG_ECHO_FILE);
            File echoFile = new File(echoFileName);
            boolean doEcho = false;
            if (echoFile.exists()) {
                if (echoFile.isFile()) {
                    if (!isEchoAppend()) {
                        echoFile.delete();
                    }
                    doEcho = true;
                } else {
                    doEcho = false;
                    say("warning \"" + echoFile + "\" is a directory. No echoing can be done.");
                }
            } else {
                doEcho = true;
            }
            if (doEcho) {
                say("logging to \"" + echoFile.getAbsolutePath() + "\", append mode = " + (isEchoAppend() ? "on" : "off"));
                echoWriter = new FileWriter(echoFile, isEchoAppend());
                echoWriter.write("\n" + RunSpacer + "\n");
                echoWriter.write("Starting migration at " + (new Date()) + "\n");
                echoWriter.write(RunSpacer + "\n");
            }
        }
    }

    protected static String RunSpacer = "===================================================";
    boolean showConnect = false;

    public boolean isEchoAppend() {
        return echoAppend;
    }

    public void setEchoAppend(boolean echoAppend) {
        this.echoAppend = echoAppend;
    }

    boolean echoAppend = true;

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
        fsm.setupEcho(inputLine);
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
        if (echoOn()) {
            echoWriter.write(RunSpacer+"\n");
            echoWriter.write("End of migration run at " + (new Date()) + "\n");
            echoWriter.write(RunSpacer+"\n");
            echoWriter.flush();
            echoWriter.close();
        }
    }

    static List<String> ALL_CONFIG_NAMES = null;

    public static List<String> getAllConfigNames() throws IllegalAccessException {
        if (ALL_CONFIG_NAMES == null) {
            ALL_CONFIG_NAMES = new ArrayList<>();
            Field[] declaredFields = FSMigrationTool.class.getDeclaredFields();
            for (Field field : declaredFields) {
                if (java.lang.reflect.Modifier.isStatic(field.getModifiers())) {
                    if (field.getName().startsWith("CONFIG_")) {
                        ALL_CONFIG_NAMES.add(field.get(FSMigrationTool.class).toString());
                    }
                }

            }
            Collections.sort(ALL_CONFIG_NAMES);
        }
        return ALL_CONFIG_NAMES;
    }
}


