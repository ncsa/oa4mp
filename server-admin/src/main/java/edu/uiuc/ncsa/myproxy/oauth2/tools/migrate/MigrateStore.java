package edu.uiuc.ncsa.myproxy.oauth2.tools.migrate;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2TStoreInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VOStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.permissions.PermissionsStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientApprovalStore;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.Pacer;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.MonitoredStoreInterface;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.cli.StoreArchiver;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.storage.monitored.Monitored;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConfiguration;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLDatabase;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.derby.DerbyConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;
import edu.uiuc.ncsa.security.storage.sql.internals.Table;

import javax.inject.Provider;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.sql.*;
import java.util.List;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.OA4MPConfigTags.*;
import static edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConstants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 2/25/24 at  7:44 AM
 */
public class MigrateStore<V extends MigrationEntry> extends SQLStore<V> {
    public static final int IMPORT_CODE_NOT_DONE = 0;
    public static final int IMPORT_CODE_SUCCESS = 1;
    public static final int IMPORT_CODE_FILE_NOT_FOUND = -1;
    public static String IMPORT_MESSAGE_FILE_NOT_FOUND = "file not found";
    public static final int IMPORT_CODE_FILE_PERMISSION = -2;
    public static String IMPORT_MESSAGE_FILE_PERMISSION = "does not have read access";
    public static final int IMPORT_CODE_FILE_IS_A_DIRECTORY = -3;
    public static String IMPORT_MESSAGE_FILE_IS_A_DIRECTORY = "is a directory";
    public static final int IMPORT_CODE_PARSE_ERROR = -4;
    public static String IMPORT_MESSAGE_PARSE_ERROR = "cannot parse entry";
    public static final int IMPORT_CODE_UNKNOWN_ERROR = -5;
    public static String IMPORT_MESSAGE_UNKNOWN_ERROR = "unknown error code";
    public static final int IMPORT_CODE_EMPTY_FILE = -6;
    public static String IMPORT_MESSAGE_EMPTY_FILE = "file is empty";
    public static final int IMPORT_CODE_COULD_NOT_READ = -7;
    public static String IMPORT_MESSAGE_COULD_NOT_READ = "could not read file";
    public static final int IMPORT_CODE_UPKEEP_SKIPPED = -8;
    public static String IMPORT_MESSAGE_UPKEEP_SKIPPED = "skipped by upkeep";


    /**
     * Use after random throwable error. Add the specific failure
     */
    public static final int IMPORT_CODE_OTHER_ERROR = -9;
    public static String IMPORT_MESSAGE_OTHER_ERROR = "";

    public static final int IMPORT_CODE_MISSING_ID = -10;
    public static String IMPORT_MESSAGE_MISSING_ID = "missing identifier: entry improperly structured";

    public static int[] ALL_FAILURE_CODES = new int[]{IMPORT_CODE_FILE_NOT_FOUND,
            IMPORT_CODE_FILE_PERMISSION,
            IMPORT_CODE_FILE_IS_A_DIRECTORY,
            IMPORT_CODE_PARSE_ERROR,
            IMPORT_CODE_UNKNOWN_ERROR,
            IMPORT_CODE_EMPTY_FILE,
            IMPORT_CODE_COULD_NOT_READ,
            IMPORT_CODE_UPKEEP_SKIPPED,
            IMPORT_CODE_OTHER_ERROR,
            IMPORT_CODE_MISSING_ID};

    String getImportMessage(Throwable t) {
        String message = t.getClass().getSimpleName() + spacer + t.getMessage();
        if (t.getCause() != null) {
            message = message + ", cause[" + t.getCause().getClass().getSimpleName() + spacer + t.getCause().getMessage() + "]";
        }
        return message;
    }

    public void setImportMessage(MigrationEntry me, int code, Throwable t) {
        me.setImportCode(code);
        me.setErrorMessage(getImportMessage(code) + spacer + getImportMessage(t));

    }

    public void setImportMessage(MigrationEntry me, int code) {
        me.setImportCode(code);
        me.setErrorMessage(getImportMessage(code));
    }

    public void setImportMessage(MigrationEntry me, Throwable t) {
        me.setErrorMessage(getImportMessage(me.getImportCode()) + spacer + t.getMessage());

    }

    public String getImportMessage(int importCode) {
        switch (importCode) {
            case IMPORT_CODE_FILE_NOT_FOUND:
                return IMPORT_MESSAGE_FILE_NOT_FOUND;
            case IMPORT_CODE_EMPTY_FILE:
                return IMPORT_MESSAGE_EMPTY_FILE;
            case IMPORT_CODE_FILE_IS_A_DIRECTORY:
                return IMPORT_MESSAGE_FILE_IS_A_DIRECTORY;
            case IMPORT_CODE_FILE_PERMISSION:
                return IMPORT_MESSAGE_FILE_PERMISSION;
            case IMPORT_CODE_PARSE_ERROR:
                return IMPORT_MESSAGE_PARSE_ERROR;
            case IMPORT_CODE_NOT_DONE:
                return null;
            case IMPORT_CODE_COULD_NOT_READ:
                return IMPORT_MESSAGE_COULD_NOT_READ;
            case IMPORT_CODE_OTHER_ERROR:
                return IMPORT_MESSAGE_OTHER_ERROR;
            case IMPORT_CODE_UNKNOWN_ERROR:
                return IMPORT_MESSAGE_UPKEEP_SKIPPED;
            case IMPORT_CODE_MISSING_ID:
                return IMPORT_MESSAGE_MISSING_ID;
            case IMPORT_CODE_UPKEEP_SKIPPED:
            default:
                return IMPORT_MESSAGE_UNKNOWN_ERROR;
        }
    }


    public MigrateStore(ConnectionPool connectionPool, Table table, Provider identifiableProvider, MapConverter converter) {
        super(connectionPool, table, identifiableProvider, converter);
    }

    protected MigrateKeys getKeys() {
        return (MigrateKeys) getMapConverter().getKeys();
    }

    @Override
    public String getCreationTSField() {
        return getKeys().create_ts();
    }

    /**
     * Gets the first batchSize undone elements for this migration.
     *
     * @param batchSize
     * @return
     */
    protected String getFetchStatement(int batchSize) {
        String s = "select * from " + getTable().getFQTablename() + " where " +
                getKeys().is_imported() + "=? AND " +
                getKeys().import_code() + "=? AND " +
                getKeys().store_type() + " =?";
        return s;
    }

    /**
     * Counts the number of entries for the given component in the database.
     *
     * @return
     */
    protected String countFetchStatement() {
        String s = "select count(*) from " + getTable().getFQTablename() + " where " +
                getKeys().is_imported() + " =? AND " +
                getKeys().import_code() + "=? AND " +
                getKeys().store_type() + " =?";
        return s;
    }

    /**
     * The statement that is used to ingest the source store.
     *
     * @return
     */
    protected String getIngestStatement() {
        String s = "insert into " + getTable().getFQTablename() +
                " (" +
                getKeys().path() + "," +
                getKeys().filename() + "," +
                getKeys().store_type() + "," +
                getKeys().import_code() + "," +
                getKeys().error_message() + "," +
                getKeys().is_imported() +
                ") values (?,?,?,?,?,false)";
        return s;
    }

    /**
     * Migration store entry after import. This reports the result of trying to import the
     * item to the store.
     *
     * @return
     */
    protected String getUpdateStatement() {
        String s = "update  " + getTable().getFQTablename() +
                "  set " +
                getKeys().is_imported() + "=?," +
                getKeys().import_code() + "=?," +
                getKeys().error_message() + "=?," +
                getKeys().import_ts() + "=?" +
                " where " + getKeys().filename() + "=? AND " + getKeys().store_type() + "=?";
        return s;
    }

    protected boolean isFS(Store store, boolean noTransactions) {
        if (!(store instanceof FileStore)) {
            return false; // skip non-file store
        }
        if (noTransactions) {
            if ((store instanceof OA2TStoreInterface) || (store instanceof TXStore)) {
                return false;
            }
        }
        return true;
    }

    protected boolean isSQLStore(Store store, boolean noTransactions) {
        if (!(store instanceof SQLStore)) {
            return false; // skip non-file store
        }
        if (noTransactions) {
            if ((store instanceof OA2TStoreInterface) || (store instanceof TXStore)) {
                return false;
            }
        }
        return true;
    }

    public void ingest(OA2SE source, boolean noTransactions,
                       int batchSize,
                       boolean pacerOn) throws SQLException {

        List<Store> stores = source.getAllStores();
        ingestionCounter = 0L;
        badIngestionCounter = 0L;
        totalByteCount = 0L;
        dbg("starting to ingest ");
        long startTime = System.currentTimeMillis();
        for (Store store : stores) {
            if (isFS(store, noTransactions)) {
                ingest((FileStore) store, batchSize, pacerOn);
            }

        } // end for
        dbg();
        dbg("elapsed ingestion time : " + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));
        dbg("      total file count : " + ingestionCounter);
        dbg("       total bad files : " + badIngestionCounter);
        dbg("      total byte count : " + totalByteCount);
    }

    long ingestionCounter = 0L;
    long badIngestionCounter = 0L;
    long totalByteCount = 0L;
    public static String[] ALL_STORE_TYPES = new String[]{
            CLIENTS_STORE,
            CLIENT_APPROVAL_STORE,
            ADMIN_CLIENT_STORE,
            PERMISSION_STORE,
            TRANSACTIONS_STORE,
            TOKEN_EXCHANGE_RECORD_STORE,
            VIRTUAL_ORGANIZATION_STORE
    };

    protected String getStoreComponent(Store s) {
        if (s instanceof OA2TStoreInterface) {
            return TRANSACTIONS_STORE;
        }
        if (s instanceof TXStore) {
            return TOKEN_EXCHANGE_RECORD_STORE;
        }
        if (s instanceof AdminClientStore) {
            return ADMIN_CLIENT_STORE;
        }
        if (s instanceof ClientStore) {
            return CLIENTS_STORE;
        }
        if (s instanceof VOStore) {
            return VIRTUAL_ORGANIZATION_STORE;
        }
        if (s instanceof PermissionsStore) {
            return PERMISSION_STORE;
        }
        if (s instanceof ClientApprovalStore) {
            return CLIENT_APPROVAL_STORE;
        }

        throw new GeneralException("unknown store type");
    }

    boolean DEEP_DEBUG = true;

    /**
     * Line feed.
     */
    void dbg() {
        if (DEEP_DEBUG) {
            System.err.println("");
        }
    }

    void dbg(String x) {
        if (DEEP_DEBUG) {
            System.err.println(getClass().getSimpleName() + ":" + x);
        }
    }

    long pacerIncrement = 1000;

    /**
     * Read all the names of the file that the OS knows about. This is designed to be quick
     * so that the system is not ovewhelmed with too much processing for huge directories.
     *
     * @param fileStore
     * @return
     * @throws SQLException
     */
    protected int[] ingest(FileStore fileStore,
                           int batchSize,
                           boolean pacerOn) throws SQLException {
        String component = getStoreComponent(fileStore);
        File dir = fileStore.getStorageDirectory();
        String dString = dir.getAbsolutePath();
        ConnectionRecord cr = getConnectionPool().pop();
        Connection c = cr.connection;
        // In Derby, if this is true, then calls return only after every file operation is done
        // This alone (from the tuning tips and tricks section of the reference) speeds up
        // large operations by a factor of 100 easily.
        c.setAutoCommit(false);
        File[] fileList = dir.listFiles();
        dbg("processing " + fileList.length + " files from " + dString + ".");
        long totalBytes = 0L; // bytes read here
        long localBadCount = 0L; // files rejected here
        long startTime = System.currentTimeMillis();
        int[] importErrorCodes = new int[ALL_FAILURE_CODES.length];
        long hzTime = startTime;

        try {
            PreparedStatement pStmt = c.prepareStatement(getIngestStatement());
            for (int i = 0; i < fileList.length; i++) {
                File f = fileList[i];
                totalBytes += f.length();
                ingestionCounter++; // total of all processed

                pStmt.setString(1, dString);
                pStmt.setString(2, f.getName());
                pStmt.setString(3, component);
                int importCode = getImportCode(f);
                if (importCode < 0) {
                    int index = importErrorCodes[Math.abs(importCode)];
                    importErrorCodes[index] = 1 + importErrorCodes[index];
                    localBadCount++;
                }
                pStmt.setInt(4, importCode);
                String importMessage = getImportMessage(importCode);

                if (importMessage == null) {
                    pStmt.setNull(5, Types.CLOB);
                } else {
                    pStmt.setString(5, importMessage);
                }
                pStmt.addBatch();
                if (pacerOn) {
                    if (1 < i && 0 == i % pacerIncrement) {
                        pacer.pace(i, " files ingested @ " + computeHerz((int) pacerIncrement, hzTime));
                        hzTime = System.currentTimeMillis();
                    }
                }
            }// end for
            dbg();
            if (pacerOn) {
                if (1 < ingestionCounter && 0 == ingestionCounter % pacerIncrement) {
                    pacer.pace(ingestionCounter, " files ingested @ " + computeHerz((int) pacerIncrement, hzTime));
                    hzTime = System.currentTimeMillis();
                }
            }
            totalByteCount += totalBytes; // total of all reads
            long startBatch = System.currentTimeMillis();
            dbg("updating migration database...");
            int[] rcs = pStmt.executeBatch();
            dbg("       store : " + component);
            dbg("       total : " + rcs.length);
            dbg("    rejected : " + localBadCount);
            dbg("update speed : " + computeHerz(rcs.length, startBatch));
            dbg("       bytes : " + StringUtils.formatByteCount(totalBytes));
            dbg("  total time : " + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));
            interpretErrorCode(importErrorCodes);
            //   pStmt.clearBatch();
            c.commit();
            pStmt.close();
            c.setAutoCommit(true); // don't leave it with auto-commit off.
            releaseConnection(cr);
            badIngestionCounter += localBadCount;
            return rcs;
        } catch (SQLException sqlException) {
            sqlException.printStackTrace();
            System.out.println("JDBC URL = " + getConnectionPool().getConnectionParameters().getJdbcUrl());
            if (sqlException.getCause() != null) {
                sqlException.getCause().printStackTrace();
            }
            getConnectionPool().destroy(cr);
            throw sqlException;
        }
    }

    protected String computeHerz(int value, long startTime) {
// rcs.length * 1000 / (System.currentTimeMillis() - startBatch) + " Hz"
        long duration = System.currentTimeMillis() - startTime;
        if (duration == 0) {
            return "0 Hz";
        }
        // trailing blanks are because Hz can vary considerable in length.
        return value * 1000 / duration + " Hz     ";
    }


    /**
     * Takes an array of errorCode (the index is the absolute value of the code)
     * and spits out all the non-zero counts.
     *
     * @param errorCodes
     */

    void interpretErrorCode(int[] errorCodes) {
        for (int i = 0; i < errorCodes.length; i++) {
            if (0 < errorCodes[i]) {
                dbg("    " + getImportMessage(-errorCodes[i]) + ":" + errorCodes[i]);
            }
        }
    }

    @Override
    public DerbyConnectionPool getConnectionPool() {
        return (DerbyConnectionPool) super.getConnectionPool();
    }


    /**
     * Does this store exist?
     *
     * @return
     */
    public boolean exists() {
        File f = new File(getConnectionPool().getConnectionParameters().getDatabaseName());
        return f.exists();
    }

    private static int getImportCode(File f) {
        int importCode = IMPORT_CODE_NOT_DONE;
        if (f.isDirectory()) {
            importCode = IMPORT_CODE_FILE_IS_A_DIRECTORY;
        }
        if (!f.canRead()) {
            importCode = IMPORT_CODE_FILE_PERMISSION;
        }
        if (!f.exists()) {
            importCode = IMPORT_CODE_FILE_NOT_FOUND;
        }
        if (f.length() == 0) {
            importCode = IMPORT_CODE_EMPTY_FILE;
        }
        return importCode;
    }

    /**
     * Main entry point for migration. This will resume where it left off as needed.
     *
     * @param targetSE
     * @param noTransactions
     * @param batchSize
     * @param runUpkeep
     * @param pacerOn
     */
    public void migrateAll(OA2SE targetSE,
                           boolean noTransactions,
                           int batchSize,
                           boolean runUpkeep,
                           boolean pacerOn
    ) {
        long startTime = System.currentTimeMillis();
        dbg("starting to migrate...");
        List<Store> stores = targetSE.getAllStores();
        for (Store store : stores) {
            try {
                if (isSQLStore(store, noTransactions)) {
                    migrate((SQLStore) store, runUpkeep, getStoreComponent(store), batchSize);
                }
            } catch (SQLNonTransientConnectionException y) {
                System.err.println("JDBC URL = " + getConnectionPool().getConnectionParameters().getJdbcUrl());
                y.printStackTrace();
            } catch (SQLException sqlException) {
                sqlException.printStackTrace();
            }
        } // end for
        dbg();
        dbg("total elapsed time : " + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));
    }

    boolean pacerOn = true;
    Pacer pacer = new Pacer(20);

    /**
     * Takes the entries in the migration table and puts them into the store. This  tracks
     * a batch update to the target store and a batch update to the migration store. This allows
     * us to resume the import if there is a failure.
     *
     * @param targetStore
     * @param component
     * @throws SQLException
     */
    protected void migrate(SQLStore targetStore,
                           boolean runUpkeep,
                           String component,
                           int batchSize) throws SQLException {
        String stmt = getFetchStatement(batchSize);
        ConnectionRecord cr = getConnectionPool().pop();
        Connection migrateConnection = cr.connection;
        long startTime = System.currentTimeMillis();
        ConnectionRecord targetCR = targetStore.getConnectionPool().pop();
        Connection targetConnection = targetCR.connection;
        // now the stats
        long totalRecords = 0;
        int[] importErrorCodes = new int[1 + ALL_FAILURE_CODES.length];
        long localBadCount = 0;
        int[] rcs = new int[]{};
        int upkept = 0;
        long hzTime = startTime;
        int importCount = 0;
        int attemptedCount = 0;
        long notImportedCount = 0;
        StoreArchiver storeArchiver = new StoreArchiver(targetStore);

        try {
            String archiveStatement = storeArchiver.createVersionStatement();
            PreparedStatement archiveStmt = targetConnection.prepareStatement(archiveStatement);
            ResultSet rs;
            String countStmt = countFetchStatement();
            PreparedStatement counterStmt = migrateConnection.prepareStatement(countStmt);
            counterStmt.setBoolean(1, false);
            counterStmt.setInt(2, 0);
            counterStmt.setString(3, component);
            rs = counterStmt.executeQuery();
            // rs.next();
            if (rs.next()) {
                totalRecords = rs.getInt(1); // *trick* to get the row count
            }
            rs.close();
            counterStmt.close();
            if (totalRecords == 0L) {
                releaseConnection(cr);
                return; // nix to do
            }
            dbg("starting to migrate " + totalRecords + " items for " + component);
            migrateConnection.setAutoCommit(false);
            targetConnection.setAutoCommit(false);

            PreparedStatement meStmt = migrateConnection.prepareStatement(stmt);
            meStmt.setBoolean(1, false);
            meStmt.setInt(2, 0);
            meStmt.setString(3, component);
            PreparedStatement meUpdateStmt = migrateConnection.prepareStatement(getUpdateStatement());
            PreparedStatement registerEntryStmt = targetConnection.prepareStatement(targetStore.getTable().createInsertStatement());

            rs = meStmt.executeQuery();

            while (rs.next()) {
                attemptedCount++;
                ColumnMap map = SQLDatabase.rsToMap(rs); // take the row in the migrate table, turn into a map.
                MigrationEntry me = create();
                populate(map, (V) me);
                File f = new File(me.path, me.filename);
                me.setErrorMessage(null);
                me.setImportCode(getImportCode(f));
                me.setImportTS(new java.util.Date());
                // error getting the file itself.
                try {

                    FileInputStream fis = new FileInputStream(f);
                    XMLMap entryMap = new XMLMap();
                    entryMap.fromXML(fis);
                    Identifiable value = targetStore.getXMLConverter().fromMap(entryMap, null);
                    boolean skip = false;
                    if (value.getIdentifier() == null) {
                        System.out.println(value);
                        me.setImportCode(IMPORT_CODE_MISSING_ID);
                        me.setErrorMessage(getImportMessage(IMPORT_CODE_MISSING_ID));
                        skip = true;
                    }
                    if (runUpkeep && !skip) {
                        if (targetStore instanceof MonitoredStoreInterface) {
                            skip = doUpkeep(((MonitoredStoreInterface) targetStore).getUpkeepConfiguration(),
                                    me, (Monitored) value,
                                    archiveStmt);
                            if (skip) {
                                upkept++; // update the stats
                            }

//                            skip = ((MonitoredStoreInterface) targetStore).getUpkeepConfiguration().applies((Monitored) value);
                        }
                    }
                    if (!skip) {
                        targetStore.doRegisterStatement(registerEntryStmt, value);
                        registerEntryStmt.addBatch();
                        me.setImportCode(IMPORT_CODE_SUCCESS);
                        me.setIdentifier(value.getIdentifier());
                        me.setDescription(value.getDescription());
                        importCount++;
                    }

                    if (0 < attemptedCount && 0 == attemptedCount % 100) {
                        if (pacerOn) {
                            pacer.pace(attemptedCount, (100 * attemptedCount / totalRecords) + "% of files migrated in " +
                                    component + " @ " +
                                    (100000 / (System.currentTimeMillis() - hzTime)) + " Hz");
                            hzTime = System.currentTimeMillis();
                        }
                    }
                } catch (FileNotFoundException fnf) {
                    setImportMessage(me, IMPORT_CODE_FILE_NOT_FOUND, fnf);
                } catch (SecurityException securityException) {
                    setImportMessage(me, IMPORT_CODE_FILE_PERMISSION, securityException);
                } catch (IOException e) {
                    setImportMessage(me, IMPORT_CODE_COULD_NOT_READ, e);
                } catch (Throwable t) {
                    setImportMessage(me, IMPORT_CODE_OTHER_ERROR, t);
                }
//  update  oauth2.migrate  set is_imported=?,import_code=?,error_message=?,import_ts=? where filename=? AND store_type=?
                meUpdateStmt.setBoolean(1, 0 < me.getImportCode());
                meUpdateStmt.setInt(2, me.getImportCode());
                if (StringUtils.isTrivial(me.getErrorMessage())) {
                    meUpdateStmt.setNull(3, Types.CLOB);
                } else {
                    meUpdateStmt.setString(3, me.getErrorMessage());
                }
                meUpdateStmt.setDate(4, new java.sql.Date(me.getImportTS().getTime()));
                meUpdateStmt.setString(5, me.getFilename());
                meUpdateStmt.setString(6, me.getStoreType());
                meUpdateStmt.addBatch();
                if (me.getImportCode() < 0) {
                    int index = importErrorCodes[Math.abs(me.getImportCode())];
                    importErrorCodes[index] = 1 + importErrorCodes[index];
                    localBadCount++;
                }
                if (0 < attemptedCount && attemptedCount % 15000 == 0) {
                    registerEntryStmt.executeBatch();
                    rcs = meUpdateStmt.executeBatch();
                    migrateConnection.commit();
                    targetConnection.commit();
                    registerEntryStmt.clearBatch();
                    meUpdateStmt.clearBatch();
                    System.gc();
                }
            } //end loop
            rs.close();
            if (pacerOn) { // get that last pace so the file totals look right
                pacer.pace(attemptedCount, " files migrated in " +
                        component + ", rejected=" +
                        localBadCount + " @ " +
                        (100000 / (System.currentTimeMillis() - hzTime)) + " Hz");
                hzTime = System.currentTimeMillis();
            }
            if (0 < importCount) {  // It is possible that, e.g. all entries are unreadable.
                registerEntryStmt.executeBatch();
                rcs = meUpdateStmt.executeBatch();
            }
            migrateConnection.commit();
            targetConnection.commit();

            registerEntryStmt.close();
            meUpdateStmt.close();
            migrateConnection.setAutoCommit(true);
            targetConnection.setAutoCommit(true);
            releaseConnection(cr);
            targetStore.releaseConnection(targetCR);
        } catch (SQLException sqlException) {
            if (DEEP_DEBUG) {
                sqlException.printStackTrace();
            }
            getConnectionPool().destroy(cr);
            targetStore.getConnectionPool().destroy(targetCR);
            throw sqlException;

        }
        dbg();
        dbg("       total : " + attemptedCount);
        dbg("    rejected : " + localBadCount);
        dbg("        time : " + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));
        dbg("   av. speed : " + computeHerz(attemptedCount, startTime));
        interpretErrorCode(importErrorCodes);
    }

    /**
     * Evaluates the entry for action. This returns true if the monitored object is skipped
     *
     * @param upkeepConfiguration
     * @param me
     * @param monitored
     * @param archiveStmt
     * @return
     */
    protected boolean doUpkeep(UpkeepConfiguration upkeepConfiguration,
                               MigrationEntry me,
                               Monitored monitored,
                               PreparedStatement archiveStmt) throws SQLException {
        String[] rcs = upkeepConfiguration.applies(monitored);
        /*
        TODO - make import code for each of these
         */
        switch (rcs[0]) {
            case ACTION_NONE:
                return false;
            case ACTION_ARCHIVE:
                me.setImportCode(IMPORT_CODE_UPKEEP_SKIPPED);
                me.setErrorMessage(rcs[1]);
                setImportMessage(me, IMPORT_CODE_UPKEEP_SKIPPED);
                archiveStmt.setString(1, me.getIdentifierString());
                return true;
            case ACTION_DELETE:
                me.setImportCode(IMPORT_CODE_UPKEEP_SKIPPED);
                me.setErrorMessage(rcs[1]);
                return true;
            case ACTION_RETAIN:
                return false;
            case ACTION_TEST:
                me.setImportCode(IMPORT_CODE_UPKEEP_SKIPPED);
                me.setErrorMessage(rcs[1]);
                return false;
        }

        return false;
    }

    String spacer = ": ";
}
