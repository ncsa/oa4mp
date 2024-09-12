package org.oa4mp.server.admin.myproxy.oauth2.tools.migrate;

import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2TStoreInterface;
import org.oa4mp.server.loader.oauth2.storage.tx.TXStore;
import org.oa4mp.server.loader.oauth2.storage.vo.VOStore;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;
import org.oa4mp.server.api.admin.permissions.Permission;
import org.oa4mp.server.api.admin.permissions.PermissionsStore;
import org.oa4mp.delegation.server.storage.ClientApproval;
import org.oa4mp.delegation.server.storage.ClientApprovalStore;
import org.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.Pacer;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.FileStore;
import edu.uiuc.ncsa.security.storage.MonitoredStoreInterface;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.monitored.Monitored;
import edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConfiguration;
import edu.uiuc.ncsa.security.storage.sql.ConnectionRecord;
import edu.uiuc.ncsa.security.storage.sql.SQLDatabase;
import edu.uiuc.ncsa.security.storage.sql.SQLStore;
import edu.uiuc.ncsa.security.storage.sql.internals.ColumnMap;

import java.io.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;

import static org.oa4mp.server.api.OA4MPConfigTags.*;
import static edu.uiuc.ncsa.security.core.util.StringUtils.RJustify;
import static edu.uiuc.ncsa.security.storage.monitored.upkeep.UpkeepConstants.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/5/24 at  7:20 AM
 */
public class FSMigrater implements MigrationConstants {
    public FSMigrater(MigrateStore migrateStore, Writer echoWriter) {
        this.migrateStore = migrateStore;
        this.echoWriter = echoWriter;
    }

    MigrateStore migrateStore;

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
        return MigrationConstants.getImportMessage(importCode);
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
        dbg("             files/sec : " + computeHerz(ingestionCounter, startTime));
    }

    long ingestionCounter = 0L;
    long badIngestionCounter = 0L;
    long totalByteCount = 0L;

    boolean DEEP_DEBUG = true;

    /**
     * Line feed.
     */
    void dbg() {
        if (DEEP_DEBUG) {
            System.err.println("");
        }
    }

    String caput = "  ";

    void dbg(String x) {
        if (DEEP_DEBUG) {
            String message =  caput + ":" + x;
            System.err.println(message);
            if(hasEchoWriter()){
                try {
                    echoWriter.write(message + "\n");
                } catch (IOException e) {
                    System.err.println("warning: echoing failed. echo is disabled:" + e.getMessage());
                    echoWriter = null;
                }
            }
        }
    }

    long pacerIncrement = 1000;

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
        ConnectionRecord cr = migrateStore.getConnectionPool().pop();
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
        int[] importErrorCodes = new int[1+ALL_FAILURE_CODES.length];
        long hzTime = startTime;

        try {
            PreparedStatement pStmt = c.prepareStatement(migrateStore.getIngestStatement());
            for (int i = 0; i < fileList.length; i++) {
                File f = fileList[i];
                totalBytes += f.length();
                ingestionCounter++; // total of all processed

                pStmt.setString(1, dString);
                pStmt.setString(2, f.getName());
                pStmt.setString(3, component.toLowerCase()); // normalize to lower case
                int importCode = getImportCode(f);
                if (importCode < 0) {
                    int index = Math.abs(importCode);
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
                        pacer.pace(i, " files read @ " + computeHerz((int) pacerIncrement, hzTime));
                        hzTime = System.currentTimeMillis();
                    }
                }
            }// end for
            dbg();
            if (pacerOn) {
                if (1 < ingestionCounter && 0 == ingestionCounter % pacerIncrement) {
                    pacer.pace(ingestionCounter, " files read @ " + computeHerz((int) pacerIncrement, hzTime));
                    hzTime = System.currentTimeMillis();
                }
            }
            totalByteCount += totalBytes; // total of all reads
            long startBatch = System.currentTimeMillis();
            dbg("ingesting...");
            int[] rcs = pStmt.executeBatch();
            // reporting
            int width=12;
            String spacer =" : ";
            dbg(RJustify("store",width) + spacer + component);
            dbg(RJustify("total",width) + spacer + rcs.length);
            dbg(RJustify("rejected",width) + spacer + localBadCount);
            dbg(RJustify("update speed",width) + spacer + computeHerz(rcs.length, startBatch));
            dbg(RJustify("bytes",width) + spacer + StringUtils.formatByteCount(totalBytes));
            dbg(RJustify("total time",width) + spacer + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));
            List<String> err = interpretErrorCode(importErrorCodes);
            if(!err.isEmpty()){
                String indent =  StringUtils.getBlanks(width + spacer.length());
                dbg(RJustify("error codes", width) + spacer + err.get(0) );
                for(int i =1 ; i < err.size(); i++) {
                    dbg(indent + err.get(i));
                }
            }
            c.commit();
            pStmt.close();
            c.setAutoCommit(true); // don't leave it with auto-commit off.
            migrateStore.releaseConnection(cr);
            badIngestionCounter += localBadCount;
            return rcs;
        } catch (SQLException sqlException) {
            sqlException.printStackTrace();
            System.out.println("JDBC URL = " + migrateStore.getConnectionPool().getConnectionParameters().getJdbcUrl());
            if (sqlException.getCause() != null) {
                sqlException.getCause().printStackTrace();
            }
            migrateStore.getConnectionPool().destroy(cr);
            throw sqlException;
        }
    }
     protected boolean hasErrorCodes(int[] importErrorCodes){
        for(int i = 0; i < importErrorCodes.length; i++){
            if(0 < importErrorCodes[i]) return true;
        }
        return false;
     }
    /**
     * Adds blanks to the output since the units may vary widely at times.  This way if this is
     * used by pacer, there are not odd artifacts at the end of the line.
     * @param value
     * @param startTime
     * @return
     */
    protected String computeHerz(long value, long startTime) {
        // trailing blanks are because Hz can vary considerably in length.
      return   StringUtils.formatHerz(value, startTime) + "          ";
    }


    /**
     * Takes an array of errorCode (the index is the absolute value of the code)
     * and spits out all the non-zero counts.
     *
     * @param errorCodes
     */

    List<String> interpretErrorCode(int[] errorCodes) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < errorCodes.length; i++) {
            if (0 < errorCodes[i]) {
                out.add(getImportMessage(-i) + ":" + errorCodes[i]);
            }
        }
        return out;
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

    public void migrate(OA2SE targetSE,
                        int batchSize,
                        boolean runUpkeep,
                        String name,
                        boolean pacerOn
    ) {
        Store store = null;
        // name is lower case
        if (name.equalsIgnoreCase(TRANSACTIONS_STORE)) {
            store = targetSE.getTransactionStore();
        }
        if (name.equalsIgnoreCase(CLIENTS_STORE)) {
            store = targetSE.getClientStore();
        }
        if (name.equalsIgnoreCase(CLIENT_APPROVAL_STORE)) {
            store = targetSE.getClientApprovalStore();
        }
        if (name.equalsIgnoreCase(ADMIN_CLIENT_STORE)) {
            store = targetSE.getAdminClientStore();
        }
        if (name.equalsIgnoreCase(VIRTUAL_ORGANIZATION_STORE)) {
            store = targetSE.getVOStore();
        }
        if (name.equalsIgnoreCase(TOKEN_EXCHANGE_RECORD_STORE)) {
            store = targetSE.getTxStore();
        }
        if (name.equalsIgnoreCase(PERMISSION_STORE)) {
            store = targetSE.getPermissionStore();
        }

        if (store == null) {
            dbg("sorry, but " + name + " is not a recognized store");
            return;
        }
        if (!(store instanceof SQLStore)) {
            dbg("sorry, but " + name + " is not an SQL store");
            return;
        }
        long startTime = System.currentTimeMillis();
        try {
            migrate((SQLStore) store, runUpkeep, getStoreComponent(store), batchSize, pacerOn);
        } catch (Throwable t) {
            dbg("Error migrating " + name + ": " + t.getMessage());
        }
        dbg("total elapsed time : " + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));

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
        List<Store> stores = targetSE.getAllStores(); // order matter, admins then clients then everything else
        for (Store store : stores) {
            try {
                if (isSQLStore(store, noTransactions)) {
                    migrate((SQLStore) store, runUpkeep, getStoreComponent(store), batchSize, pacerOn);
                    // The next two need to be current. It is possible this gets stopped and restarted,
                    // so ask the store after import has finished.
                    if (store instanceof ClientStore) {
                        clientID = new HashSet<>();
                        setIDs((SQLStore) store, clientID);
                    }
                    if (store instanceof AdminClientStore) {
                        adminIDs = new HashSet<>();
                        setIDs((SQLStore) store, adminIDs);
                    }
                }
            } catch (SQLException sqlException) {
                sqlException.printStackTrace();
            }
        } // end for
        dbg();
        dbg("total elapsed migration time : " + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));
    }

    HashSet<Identifier> adminIDs = new HashSet<>();
    HashSet<Identifier> clientID = new HashSet<>();
    boolean pacerOn = true;
    Pacer pacer = new Pacer(20);

    protected String getAllIDs(SQLStore sqlStore) {
        return "select " + sqlStore.getMapConverter().getKeys().identifier() + " from " + sqlStore.getTable().getFQTablename();
    }

    protected void setIDs(SQLStore sqlStore, HashSet<Identifier> ids) throws SQLException {
        ConnectionRecord connectionRecord = sqlStore.getConnection();
        Connection connection = connectionRecord.connection;
        try {
            Statement statement = connection.createStatement();
            ResultSet rs = statement.executeQuery(getAllIDs(sqlStore));
            while (rs.next()) {
                Identifier id = BasicIdentifier.newID(rs.getString(1));
                ids.add(id);
            }
            rs.close();
            statement.close();
            sqlStore.releaseConnection(connectionRecord);

        } catch (SQLException sqlException) {
            sqlStore.destroyConnection(connectionRecord);
            if (DEEP_DEBUG) {
                sqlException.printStackTrace();
            }
            throw sqlException;
        }
    }

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
                           int batchSize,
                           boolean pacerOn) throws SQLException {
        String stmt = migrateStore.getFetchStatement(batchSize);
        ConnectionRecord cr = migrateStore.getConnectionPool().pop();
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

        try {
            ResultSet rs;
            String countStmt = migrateStore.countFetchStatement();
            PreparedStatement counterStmt = migrateConnection.prepareStatement(countStmt);
            counterStmt.setBoolean(1, false);
            counterStmt.setInt(2, 0);
            counterStmt.setString(3, component.toLowerCase());
            rs = counterStmt.executeQuery();
            // rs.next();
            if (rs.next()) {
                totalRecords = rs.getInt(1); // *trick* to get the row count
            }
            rs.close();
            counterStmt.close();
            if (totalRecords == 0L) {
                migrateStore.releaseConnection(cr);
                return; // nix to do
            }
            dbg();
            dbg("migrating " + totalRecords + " items for " + component);
            migrateConnection.setAutoCommit(false);
            targetConnection.setAutoCommit(false);

            PreparedStatement meStmt = migrateConnection.prepareStatement(stmt);
            meStmt.setBoolean(1, false);
            meStmt.setInt(2, 0);
            meStmt.setString(3, component.toLowerCase());
            PreparedStatement meUpdateStmt = migrateConnection.prepareStatement(migrateStore.getUpdateStatement());
            PreparedStatement registerEntryStmt = targetConnection.prepareStatement(targetStore.getTable().createInsertStatement());

            rs = meStmt.executeQuery();

            while (rs.next()) {
                attemptedCount++;
                ColumnMap map = SQLDatabase.rsToMap(rs); // take the row in the migrate table, turn into a map.
                MigrationEntry me = migrateStore.create();
                migrateStore.populate(map, me);
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
                    if (value.getIdentifier() == null) {
                        // case that the object is too munged for deserialization. It may be partially readable,
                        // but a missing ID means the file never was part of the store.
                        System.out.println(value);
                        me.setImportCode(IMPORT_CODE_MISSING_ID);
                        me.setErrorMessage(getImportMessage(IMPORT_CODE_MISSING_ID));
                    }
                    if (0 == me.getImportCode()) {
                        if (!doCheck(value)) {
                            setImportMessage(me, IMPORT_CODE_NO_CORRESPONDING_ENTRY);
                        }
                    }
                    if (0 == me.getImportCode()) {
                        if (runUpkeep) {

                            if (targetStore instanceof MonitoredStoreInterface) {
                                MonitoredStoreInterface monitoredStoreInterface = (MonitoredStoreInterface) targetStore;
                                if (monitoredStoreInterface.hasUpkeepConfiguration()) {
                                    doUpkeep(monitoredStoreInterface.getUpkeepConfiguration(),
                                            me,
                                            (Monitored) value);
                                    if (me.getImportCode() < 0) {
                                        upkept++; // update the stats
                                        localBadCount--; // don't count upkept as bad.
                                    }
                                }
                            }
                        }
                    }

                    if (0 <= me.getImportCode()) {
                        // reminder: 0 means not processed, so migrate it.
                        // Positive means migrate, but with special note already set in me.
                        targetStore.doRegisterStatement(registerEntryStmt, value);
                        registerEntryStmt.addBatch();
                        if (0 == me.getImportCode()) {
                            // was nots et elsewhere, do it here. No message needed
                            me.setImportCode(IMPORT_CODE_SUCCESS);
                        }
                        me.setIdentifier(value.getIdentifier());
                        me.setDescription(value.getDescription());
                        importCount++;
                    }

                    if (pacerOn && (0 < attemptedCount && 0 == attemptedCount % 100)) {
                            pacer.pace(attemptedCount, (100 * attemptedCount / totalRecords) + "% of files read in " +
                                    component + " @ " +
                                    (100000 / (System.currentTimeMillis() - hzTime)) + " Hz" + (runUpkeep ? (" upkept=" + upkept) : ""));
                            hzTime = System.currentTimeMillis();
                    }
                } catch (FileNotFoundException fnf) {
                    setImportMessage(me, IMPORT_CODE_FILE_NOT_FOUND, fnf);
                } catch (SecurityException securityException) {
                    setImportMessage(me, IMPORT_CODE_FILE_PERMISSION, securityException);
                } catch (IOException e) {
                    setImportMessage(me, IMPORT_CODE_COULD_NOT_READ, e);
                } catch (Throwable t) {
                    t.printStackTrace();
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
                meUpdateStmt.setString(6, me.getStoreType().toLowerCase());
                meUpdateStmt.addBatch();
                if (me.getImportCode() < 0) {
                    int index = Math.abs(me.getImportCode());
                    importErrorCodes[index] = 1 + importErrorCodes[index]; // increment counter
                    localBadCount++;
                }
                if (0 < batchSize && 0 < importCount && importCount % batchSize == 0) {
                    // only triggers a batch when there are enough
                    if(pacerOn){
                        pacer.clear();
                        pacer.pace(batchSize,"updating store...");
                    }
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
                pacer.pace(importCount, " files migrated in " +
                        component + ", rejected=" +
                        localBadCount + " @ " +
                        (100000 / (System.currentTimeMillis() - hzTime)) + " Hz" + (runUpkeep ? (" upkept=" + upkept) : ""));
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
            migrateStore.releaseConnection(cr);
            targetStore.releaseConnection(targetCR);
        } catch (SQLException sqlException) {
            if (DEEP_DEBUG) {
                sqlException.printStackTrace();
            }
            migrateStore.getConnectionPool().destroy(cr);
            targetStore.getConnectionPool().destroy(targetCR);
            throw sqlException;

        }
        dbg();
        int width = 12;
        String spacer = " : ";
        dbg(RJustify("total",width) +spacer + attemptedCount);
        dbg(RJustify("upkept",width) +spacer + upkept);
        dbg(RJustify("bad files",width) +spacer + localBadCount);
        dbg(RJustify("net files",width) +spacer + importCount);
        dbg(RJustify("time",width) +spacer + StringUtils.formatElapsedTime(System.currentTimeMillis() - startTime));
        dbg(RJustify("av. speed",width) +spacer + computeHerz(attemptedCount, startTime));
        List<String> err = interpretErrorCode(importErrorCodes);
        if(!err.isEmpty()){
            String indent =  StringUtils.getBlanks(width + spacer.length());
            dbg(RJustify("error codes", width) + spacer + err.get(0) );
            for(int i =1 ; i < err.size(); i++) {
                dbg(indent + err.get(i));
            }
        }
    }

    protected boolean doCheck(Identifiable identifiable) {
        if (identifiable instanceof Permission) {
            return permissionCheck((Permission) identifiable);
        }
        if (identifiable instanceof ClientApproval) {
            return approvalCheck((ClientApproval) identifiable);
        }
        return true;
    }

    /**
     * Checks if the permission actually points to anything in the store.
     *
     * @param permission
     * @return
     */
    protected boolean permissionCheck(Permission permission) {
        return clientID.contains(permission.getClientID()) || adminIDs.contains(permission.getAdminID());
    }

    protected boolean approvalCheck(ClientApproval clientApproval) {
        return clientID.contains(clientApproval.getIdentifier());
    }

    /**
     * Evaluates the entry for action. This returns true if the monitored object is skipped
     *
     * @param upkeepConfiguration
     * @param me
     * @param monitored
     * @return
     */
    protected boolean doUpkeep(UpkeepConfiguration upkeepConfiguration,
                               MigrationEntry me,
                               Monitored monitored) throws SQLException {
        if (upkeepConfiguration == null) {
            return false;
        }
        String[] rcs = upkeepConfiguration.applies(monitored);
        switch (rcs[0]) {
            case ACTION_NONE:
                // Target store has this added.
                return false;
            case ACTION_ARCHIVE:
                // Target store gets a new vesion of this only.
                me.setImportCode(IMPORT_CODE_UPKEEP_ARCHIVED);
                me.setErrorMessage(rcs[1]);
                String oldID = monitored.getIdentifierString();
                String newID = oldID + Store.VERSION_TAG + "=0";
                monitored.setIdentifier(BasicIdentifier.newID(newID));
                return true;
            case ACTION_DELETE:
                // Not saved anywhere. So it is deleted from the source store
                me.setImportCode(IMPORT_CODE_UPKEEP_DELETED);
                me.setErrorMessage(rcs[1]);
                return true;
            case ACTION_RETAIN:
                //
                return false;
            case ACTION_TEST:
                me.setImportCode(IMPORT_CODE_UPKEEP_TEST_ONLY); // positive value ==> ok.
                me.setErrorMessage(rcs[1]);
                return false;
        }

        return false;
    }

    String spacer = ": ";
    Writer echoWriter = null;
    protected boolean hasEchoWriter(){
        return echoWriter != null;
    }
}
