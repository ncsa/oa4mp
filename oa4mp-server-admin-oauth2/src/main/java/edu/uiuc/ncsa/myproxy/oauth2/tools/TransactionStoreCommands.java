package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.TokenExchangeRecordRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenRetentionPolicy;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2TStoreInterface;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2TransactionKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXStore;
import edu.uiuc.ncsa.myproxy.oa4mp.qdl.claims.ConfigtoCS;
import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.cache.LockingCleanup;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.net.URI;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static edu.uiuc.ncsa.security.core.cache.LockingCleanup.lockID;
import static edu.uiuc.ncsa.security.core.util.StringUtils.pad2;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/16/20 at  3:16 PM
 */
public class TransactionStoreCommands extends StoreCommands2 {

    public static final String ALL = "-all";
    public static final String VERBOSE = "-v";
    public static final String TEST = "-test";
    public static final String FORCE = "-force";
    public static final String HOST = "-host";
    public static final String ROLLBACK = "-O7";
    public static final String RESULT_SET = "-rs";

    public TransactionStoreCommands(MyLoggingFacade logger, String defaultIndent, OA2SE oa2se) {
        super(logger, defaultIndent, oa2se.getTransactionStore());
        this.oa2se = oa2se;
        this.txStore = oa2se.getTxStore();
    }

    OA2SE oa2se;

    public TXStore getTxStore() {
        return txStore;
    }

    TXStore<? extends TXRecord> txStore;

    public TransactionStoreCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "transactions";
    }

    @Override
    public boolean update(Identifiable identifiable) throws IOException {
        say("Mass update not implemented yet. You can still update individual properties");
        return false;
    }

    @Override
    public void extraUpdates(Identifiable identifiable) throws IOException {

    }

    @Override
    protected String format(Identifiable identifiable) {
        OA2ServiceTransaction t = (OA2ServiceTransaction) identifiable;
        return t.getIdentifierString() + " auth time: " + t.getAuthTime();
    }

    public void tokens(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showExpHelp();
            return;
        }
        OA2ServiceTransaction t = (OA2ServiceTransaction) findItem(inputLine);
        if (t == null) {
            say("sorry, that transaction does not currently exist. ");
        }
        int width = 30;
        String stile = " | ";
        boolean showAG = true;
        boolean showAT = true;
        boolean showRT = true;
        if (0 < inputLine.getArgCount()) {
            showAG = inputLine.hasArg("-ag");
            showAT = inputLine.hasArg("-at");
            showRT = inputLine.hasArg("-rt");
        }
        if ((!showAG && showAT && showRT)) {
            return;
        }

        say(pad2("token type", 15)
                + stile
                + "jwt"
                + stile
                + pad2("valid", 7)
                + stile
                + pad2("issued at", width)
                + stile
                + pad2("expires at", width)
                + stile
                + "lifetime (ms.)");
        if (showAG) {
            showExp("auth grant",
                    DateUtils.MAX_TIMEOUT,
                    t.isAuthGrantValid(),
                    (TokenImpl) t.getAuthorizationGrant(),
                    width,
                    stile);
        }
        if (showAT) {
            if (!t.hasAccessToken()) {
                say(pad2("access token", 15) + stile + "-----");
            } else {
                showExp("access token",
                        t.getAccessTokenLifetime(),
                        t.isAccessTokenValid(),
                        (TokenImpl) t.getAccessToken(),
                        width,
                        stile);
            }
        }
        if (showRT) {
            if (!t.hasRefreshToken()) {
                say(pad2("refresh token", 15) + stile + "-----");
            } else {
                showExp("refresh token",
                        t.getRefreshTokenLifetime(),
                        t.isRefreshTokenValid(),
                        (TokenImpl) t.getRefreshToken(),
                        width,
                        stile);
            }
        }


    }

    protected void showExp(String tokenName,
                           long lifetime,
                           boolean isValid,
                           TokenImpl token,
                           int width,
                           String stile) {
        Date d = DateUtils.getDate(token.getToken());
        Date expDate = new Date();
        long exp = d.getTime() + lifetime;

        boolean isExpired = expDate.getTime() < exp; // expDate is still current time
        expDate.setTime(exp);
        // now to figure out what type of token it is.
        boolean isJWT = false;
        try {
            JSONObject j = JSONObject.fromObject(token.getToken());
            isJWT = true;
        } catch (Throwable t) {
            // rock on
        }
        say(pad2((isExpired ? "" : "*") + tokenName, 15)
                + stile
                + (isJWT ? " y " : " n ")
                + stile
                + pad2("   " + (isValid ? "y" : "n"), 7)
                + stile
                + pad2(d, false, width)
                + stile
                + pad2(expDate, false, width)
                + stile
                + lifetime
        );
    }

    private void showExpHelp() {
        say("tokens [-at | -rt | -ag]");
        sayi("Show information about tokens such as if its a jwt, validity, issue time, expiration times, etc. in human readable format");
        sayi("No arguments means show everything. Flags are");
        sayi("-ag = authorization grant");
        sayi("-at = access token");
        sayi("-rt = refresh token");

        sayi("If the tokens are not set, that is shown too with a set of ----");
        sayi("An asterisk before the token name means that that token has expired.");
    }

    public void claims(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            showClaimsHelp();
            return;
        }
        OA2ServiceTransaction t = (OA2ServiceTransaction) findItem(inputLine);
        if (t.getUserMetaData() != null) {

            say(t.getUserMetaData().toString(1));
        } else {
            say("(no claims found)");
        }
    }

    private void showClaimsHelp() {
        say("claims");
        sayi("Show the claims associated with this transaction. These are mostly used to create the id token");
    }

    public static final String LS_AT_FLAG = "-at";
    public static final String LS_RT_FLAG = "-rt";

    /**
     * note that this (and {@link #getIDByRT(InputLine)} are a bit specific in that they look things up
     * by the JTI of the  token, so quite a bit of proessign has been done already to get to this point.
     *
     * @param inputLine
     * @return
     */
    protected Identifier getIDbyAT(InputLine inputLine) {
        String rawAT = inputLine.getNextArgFor(LS_AT_FLAG);
        if (StringUtils.isTrivial(rawAT)) {
            return null;
        }
        AccessTokenImpl at = new AccessTokenImpl(URI.create(rawAT));
        OA2ServiceTransaction serviceTransaction = (OA2ServiceTransaction) ((TransactionStore) getStore()).get(at);
        if (serviceTransaction != null) {
            return serviceTransaction.getIdentifier();
        } else {
            // try to get it from the TXStore
            TXRecord txRecord = (TXRecord) getTxStore().get(BasicIdentifier.newID(rawAT));
            if (txRecord != null) {
                return txRecord.getParentID();
            }
        }
        return null;
    }

    protected Identifier getIDByRT(InputLine inputLine) {
        String rawRT = inputLine.getNextArgFor(LS_RT_FLAG);
        if (StringUtils.isTrivial(rawRT)) {
            return null;
        }
        // Do the same thing as per above but with refresh tokens.
        RefreshTokenImpl rt = new RefreshTokenImpl(URI.create(rawRT));
        OA2ServiceTransaction serviceTransaction = ((RefreshTokenStore) getStore()).get(rt);
        if (serviceTransaction != null) {
            return serviceTransaction.getIdentifier();
        } else {
            // try to get it from the TXStore
            TXRecord txRecord = (TXRecord) getTxStore().get(BasicIdentifier.newID(rawRT));
            if (txRecord != null) {
                return txRecord.getParentID();
            }
        }

        return null;
    }

    @Override
    public void ls(InputLine inputLine) {
        // strategy is to fund the actual id and use that to construct the right input line
        // and pass it off to the super function so we don't have to re-invent the wheel.
        if (showHelp(inputLine)) {
            showLSHelp();
            say("For transaction stores, you may also specify listing by using the access token or refresh token:");
            say("ls [" + LS_AT_FLAG + " | " + LS_RT_FLAG + " token]");
            say("Note that other switches, such as " + VERBOSE_COMMAND + " work as well.");
            return;
        }
        if (inputLine.hasArg(LS_AT_FLAG)) {
            Identifier identifier = getIDbyAT(inputLine);
            if (identifier == null) {
                say("sorry, but no argument supplied.");
                return;
            }
            inputLine.removeSwitchAndValue(LS_AT_FLAG);
            inputLine.appendArg("/" + identifier);
        }

        if (inputLine.hasArg(LS_RT_FLAG)) {
            Identifier identifier = getIDByRT(inputLine);
            if (identifier == null) {
                say("sorry, but no argument supplied.");
                return;
            }
            inputLine.removeSwitchAndValue(LS_RT_FLAG);
            inputLine.appendArg("/" + identifier);
        }

        super.ls(inputLine);
    }

    public void set_qdl_state(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set_qdl_state " + CL_INPUT_FILE_FLAG + " file_path id");
            say("replace the qdl state in the transaction with the contents of the file.");
            say("Note that the file is XML and will be converted as needed.");
            say("See also: show_qdl_state");
            return;
        }
        if (!inputLine.hasArg(CL_INPUT_FILE_FLAG)) {
            say("sorry, but you must specify a file");
            return;
        }
        String f = inputLine.getNextArgFor(CL_INPUT_FILE_FLAG);
        inputLine.removeSwitchAndValue(CL_OUTPUT_FILE_FLAG);
        OA2ServiceTransaction t = (OA2ServiceTransaction) findItem(inputLine);
        if (t == null) {
            say("sorry, I cannot find that transaction.");
            return;
        }
        String rawFile = FileUtil.readFileAsString(f);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos);
        gzipOutputStream.write(rawFile.getBytes("UTF-8"));
        gzipOutputStream.flush();
        gzipOutputStream.close();
        String encoded = Base64.encodeBase64URLSafeString(baos.toByteArray());
        t.setScriptState(encoded);
        say("done!");
    }

    public void show_qdl_state(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("show_qdl_state [" + LS_AT_FLAG + "|" + LS_RT_FLAG + " " + CL_OUTPUT_FILE_FLAG + " file_path] id");
            say("Find the given transaction, get the current state from QDL and decode it.");
            say(CL_OUTPUT_FILE_FLAG + " file_path = You may optionally save it to a file.");
            return;
        }
        String f = null;
        boolean saveFile = false;
        if (inputLine.hasArg(CL_OUTPUT_FILE_FLAG)) {
            saveFile = true;
            f = inputLine.getNextArgFor(CL_OUTPUT_FILE_FLAG);
            inputLine.removeSwitchAndValue(CL_OUTPUT_FILE_FLAG);
        }
        if (inputLine.hasArg(LS_AT_FLAG)) {
            Identifier identifier = getIDbyAT(inputLine);
            if (identifier == null) {
                say("sorry, but no argument supplied.");
                return;
            }
            inputLine.removeSwitchAndValue(LS_AT_FLAG);
            inputLine.appendArg("/" + identifier);
        } else {
            if (inputLine.hasArg(LS_RT_FLAG)) {
                Identifier identifier = getIDByRT(inputLine);
                if (identifier == null) {
                    say("sorry, but no argument supplied.");
                    return;
                }
                inputLine.removeSwitchAndValue(LS_RT_FLAG);
                inputLine.appendArg("/" + identifier);
            } else {
                // arg count of zero implies use the currently set id. If they supplied an
                // identifier, try to unscramble that.
                if (0 < inputLine.getArgCount()) {
                    // no flag, just an id or integer.
                    String lastArg = inputLine.getLastArg();
                    if (lastArg.startsWith("/")) {
                        // do nothing
                    } else {
                        if (lastArg.matches("^[0-9]*$")) {
                            //digits only, do nothing
                        } else {
                            inputLine.removeArgAt(inputLine.getArgCount());
                            lastArg = "/" + lastArg;
                            inputLine.appendArg(lastArg);
                        }
                    }
                }

            }

        }


        OA2ServiceTransaction transaction = (OA2ServiceTransaction) findItem(inputLine);
        if (transaction == null) {
            say("transaction not found.");
            return;
        }
        String rawState = transaction.getScriptState();

        if (StringUtils.isTrivial(rawState)) {
            return; // nothing to show
        }
        // now the hard bit. This is base 64 encoded, gzipped XML.
        byte[] xx = Base64.decodeBase64(rawState);
        ByteArrayInputStream bais = new ByteArrayInputStream(xx);
        // Reconstruct the XML as a string, preserving whitespace.
        GZIPInputStream gzipInputStream = new GZIPInputStream(bais, 65536);
        Reader in = new InputStreamReader(gzipInputStream);

        final int bufferSize = 1024;
        final char[] buffer = new char[bufferSize];
        final StringBuilder out = new StringBuilder();
        for (; ; ) {
            int rsz = in.read(buffer, 0, buffer.length);
            if (rsz < 0)
                break;
            out.append(buffer, 0, rsz);
        }
        if (saveFile) {
            try {
                FileUtil.writeStringToFile(f, out.toString());
                say("saved QDL state to '" + f + "'");
            } catch (Throwable e) {
                say("saving to '" + f + " failed:" + e.getMessage());
                if (isVerbose() && isPrintOuput()) {
                    e.printStackTrace();
                }
            }

        } else {
            say(out.toString());
        }
    }

    public void get_by_at(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("get_by_at access_token - get a transaction by its access token");
            return;
        }
        AccessTokenImpl at = new AccessTokenImpl(URI.create(inputLine.getLastArg()));
        OA2ServiceTransaction serviceTransaction = (OA2ServiceTransaction) ((TransactionStore) getStore()).get(at);
        if (serviceTransaction == null) {
            // look in tx store
            TXRecord txRecord = (TXRecord) getTxStore().get(at);
            Identifier parentID = txRecord.getParentID();
            serviceTransaction = (OA2ServiceTransaction) getStore().get(parentID);
        }
        if (serviceTransaction == null) {
            say("no transaction found");
            return;
        }

        format(serviceTransaction);
    }

    /**
     * Does a basic garbage collection check against the {@link RefreshTokenRetentionPolicy}.
     * This component does not have access to the full service environment so cannot quite
     * reconstruct the exact call: It will assume safeGC mode is set to false.
     *
     * @param inputLine
     * @throws Exception
     */
    public void gc_check(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("gc_check [id|index] = check if the transaction would get garbage collected");
            say("                      in the current environment.");
            say("Note that the check is done assuming safe GC mode on the server is false.");
            return;
        }
        Identifiable identifiable = findItem(inputLine);
        if (identifiable == null) {
            say("Sorry, transaction not found");
            return;
        }
        RefreshTokenRetentionPolicy refreshTokenRetentionPolicy =
                new RefreshTokenRetentionPolicy((RefreshTokenStore) getStore(), getTxStore(), "", false);
        say("retain? " + refreshTokenRetentionPolicy.retain(identifiable.getIdentifier(), identifiable));
    }

    public static String GC_SAFE_MODE_FLAG = "-safe_gc";
    public static String GC_TEST_FLAG = TEST;
    public static String GC_SIZE_FLAG = "-size";
    public static String GC_FILE_FLAG = "-file";

    public void gc_run(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("gc -run [" +
                    GC_SAFE_MODE_FLAG + " address] [" +
                    GC_TEST_FLAG + "]  [" +
                    GC_FILE_FLAG + " output_file]  [" +
                    GC_SIZE_FLAG + "] - run garbage collection on the transaction store");
            say(GC_SAFE_MODE_FLAG + " - if present, run in safe mode so that only those transactions in the ");
            say("        correct scheme and host will be garbage collected");
            say(GC_TEST_FLAG + " - if present, only test which would be garbage collected");
            say(GC_SIZE_FLAG + " - if present, print  number of transactions found ");
            say(GC_FILE_FLAG + " file - writes the ids to the output file.");
            say("E.g.");
            say("gc_run " + GC_SAFE_MODE_FLAG + " https://cilogon.org");
            say("would only remove transactions that start with https://cilogon.org ");
            say("\nThe default is to apply garbage collection to every entry in the transaction store");
            return;
        }
        boolean printSize = inputLine.hasArg(GC_SIZE_FLAG);
        inputLine.removeSwitch(GC_SIZE_FLAG);
        boolean testMode = inputLine.hasArg(GC_TEST_FLAG);
        inputLine.removeSwitch(GC_TEST_FLAG);
        boolean doOutput = inputLine.hasArg(GC_FILE_FLAG);
        String outFile = null;
        if (doOutput) {
            outFile = inputLine.getNextArgFor(GC_FILE_FLAG);
            inputLine.removeSwitchAndValue(GC_FILE_FLAG);
        }
        if (!testMode && !isBatchMode()) {
            if (!readline("Are you SURE? (yes/no)").equals("yes")) {
                say("aborting...");
                return;
            }
        }
        boolean safeGC = false;
        String address = "";
        if (inputLine.hasArg(GC_SAFE_MODE_FLAG)) {
            safeGC = true;
            address = inputLine.getNextArgFor(GC_SAFE_MODE_FLAG);
            inputLine.removeSwitchAndValue(GC_SAFE_MODE_FLAG);
        }
        if (testMode) {
            say("testing transaction record cleanup");
        } else {
            say("cleaning up transaction records");
        }

        LockingCleanup transactionCleanup = new LockingCleanup(null, "transaction cleanup");
        transactionCleanup.setCleanupInterval(0L); // run it now
        transactionCleanup.setStore(getStore());
        transactionCleanup.setTestMode(testMode);
        transactionCleanup.addRetentionPolicy(
                new RefreshTokenRetentionPolicy(
                        (RefreshTokenStore) getStore(),
                        getTxStore(),
                        address,
                        safeGC));
        transactionCleanup.setStopThread(false);
        List<OA2ServiceTransaction> transactions = transactionCleanup.age();
        FileWriter fileWriter = null;
        File file = null;

        if (doOutput) {
            file = new File(outFile);
            fileWriter = new FileWriter(file);
            for (OA2ServiceTransaction t : transactions) {
                fileWriter.write(t.getIdentifierString() + "\n");
            }
            //   fileWriter.flush();
            //    fileWriter.close();
            say("wrote transaction ids to " + file.getAbsolutePath());
            if (printSize) {
                say(transactions.size() + " transactions found of " + getStore().size() + " to garbage collect");
            }
        } else {
            if (!printSize) {
                for (OA2ServiceTransaction t : transactions) {
                    say(t.getIdentifierString());
                }
            }
            say(transactions.size() + " transactions found of " + getStore().size() + " to garbage collect");
        }

        if (testMode) {
            say("testing token exchange record cleanup");
        } else {
            say("cleaning up token exchange records");
        }
        Cleanup txRecordCleanup = new Cleanup<>(null, "TX record cleanup");
        txRecordCleanup.setCleanupInterval(1);
        txRecordCleanup.setStopThread(false);

        txRecordCleanup.setMap(getTxStore());
        txRecordCleanup.setTestMode(testMode);
        txRecordCleanup.addRetentionPolicy(new TokenExchangeRecordRetentionPolicy(address, safeGC));
        List<TXRecord> txRecords = txRecordCleanup.age();
        if (doOutput) {
            fileWriter.write(""); // blank line between
            for (TXRecord t : txRecords) {
                fileWriter.write(t.getIdentifierString() + "\n");
            }
            fileWriter.flush();
            fileWriter.close();
            say("wrote tx record ids to " + file.getAbsolutePath());
            if (printSize) {
                say(txRecords.size() + " tx records found of " + getTxStore().size() + " to garbage collect");
            }
        } else {
            if (!printSize) {
                for (TXRecord t : txRecords) {
                    say(t.getIdentifierString());
                }
            }
            say(txRecords.size() + " tx records found of " + getTxStore().size() + " to garbage collect");

        }
    }

    // Todo: Have a general gc facility to test, lock, unlock, etc???
    public static String GC_CHECK_FLAG = "-check";
    public static String GC_RUN_FLAG = "-run";
    public static String GC_IS_LOCKED_FLAG = "-?";
    public static String GC_IS_UNLOCK_FLAG = "-unlock";
    public static String GC_IS_LOCK_FLAG = "-lock";
    public static String GC_IS_ALARMS_FLAG = "-alarms";


    public void gc_lock(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("gc_lock [-rm | ? | -alarms]");
            say("(no arg) - lock the transaction and TX stores");
            say("-rm - remove any locks");
            say("? - report if stores are locked.");
            say("-alarms - show configured alarms");
            return;
        }
        if (inputLine.hasArg("-alarms")) {
            if (oa2se.hasCleanupAlarms()) {
                say("alarms set for " + oa2se.getCleanupAlarms());
            } else {
                say("no configured alarms. Cleanup interval is " + oa2se.getCleanupInterval());
            }
            return;
        }
        if (inputLine.hasArg("?")) {
            say("transactions locked? " + getStore().containsKey(lockID));
            say("TX store locked? " + getTxStore().containsKey(lockID));
            return;
        }
        if (inputLine.hasArg("-rm")) {
            say("removing locks...");
            boolean t = null == getStore().remove(lockID);
            boolean tx = null == getTxStore().remove(lockID);
            say((t ? "did not remove" : "removed") + " transaction store lock");
            say((tx ? "did not remove" : "removed") + " TX store store lock");
            return;
        }
        Identifiable tLock = getStore().create();
        tLock.setIdentifier(lockID);
        getStore().save(tLock);
        say("transaction store locked");

        tLock = getTxStore().create();
        tLock.setIdentifier(lockID);
        getTxStore().save(tLock);
        say("TX store locked");
        // lock, unlock, is locked
    }

    void showPatchHelp() {
        say(PATCH_NAME + " [" + ALL + "] [" + VERBOSE + "] [" + TEST + "] [" + FORCE + "] [" + HOST + " address] [" + ROLLBACK + "] [" + RESULT_SET + "] id]");
        say("(no arg) - if an id is set, reconcile the current transaction. Otherwise do nothing.");
        say(ALL + " - If present, finds ALL transaction to reconcile. May be restricted by " + HOST);
        say(FORCE + " - if the target exists overwrite. Default is to not overwrite an existing target.");
        say(HOST + " address - restrict ids to those with the given address for the host, e.g. -host test.cilogon.org ");
        say(ROLLBACK + " - normal operation takes O7 serialization and converts to O8. If " + ROLLBACK + " is given,");
        say("         then the JSON serialization is used to create the O7 serialization.");
        say("         I.e. Normal is O7 --> O8, this switch does O8 --> O7.");
        say(RESULT_SET + " - store the processed and unprocessed transactions in results sets named");
        say("         resp. 'good' and 'bad'. You may then explore them like any other result set.");
        say("         See help for the rs command for more.");
        say(TEST + " - simply carry out the operation but do not save it. Print what would happen.");
        say(VERBOSE + " - verbose mode. Print out a note for id of every transaction as processed.");
        say("O7 stashed the serialized claim sources in the states attribute (a JSON object) with the");
        say("key claims_sources. O8 adds it own key, claims_sources2, and uses that. Normal operation");
        say("of this command takes what in claims_sources converts it to JSON then stashes is in claims_sources2.");
        say("The " + ROLLBACK + " switch reads claims_sources2 and recreates claims_sources.");
        say("Note that this is intended to only run under 5.2.7.1. Everything is very version sensitive.");
    }

    void showMorePatchHelp() {
        say("The problem ");
        say("-----------");
        say("Until O7 (=5.2.7 OA4MP) claim sources used java serialization when creating the transaction");
        say("O8 (=5.2.8+) uses Java 11 and Oracle changed the serialization mechanism for security reasons.");
        say("»Therefore such transactions are not forward compatible from 5.2.7 to 5.2.8«");
        say("The solution is to start using JSON for serialization, requiring O7 transactions");
        say("to be converted. This one-time operation is done with this command.");
        say("");
        say("You can view the states property in the CLI by using the transactions component, setting the id you want listing it");
        say(">transactions set_id XXX");
        say(">transactions ls -v -keys [states]");
        say("   states : {\"comment\":\"State for object id...(whole buncha stuff)");
        say("");
        say("Normal operation");
        say("----------------");
        say("This converts O7 transactions to O8.  A typical invocation would be");
        say("\n" + PATCH_NAME + " " + ALL + " " + HOST + " \"cilogon.org\" -v\n");
        say("which would convert all of the transactions for the given host and be relatively chatty about it.");
        say("If you have already run this and need to run it again, it will skip any transactions it thinks were converted");
        say("You can force it to process everything using the " + FORCE + " option.");
        say("\nUsing the " + ROLLBACK + " switch ('rollback')");
        say("--------------");
        say("In the case that O8 is deployed and needs to be downgraded to O7, any transactions created by it");
        say("must be made compatible with O7. This is the function of the " + ROLLBACK + " option.");
        say("To use it, downgrade the server and as soon as it is up, run ");
        say("\n" + PATCH_NAME + " " + FORCE + " " + ROLLBACK + " " + ALL + "\n");
        say("This converts every outstanding transaction, you might also want to restrict it using the -host option.");
        say("You need to force this, to overwrite the Java serialized object, since that is for Java 11, not Java 8. ");

    }

    // must be same as next function so documentation is correct.
    // MUST BE A VERB like reconcile, patch or some such or the English in the documentation gets hinky.
    String PATCH_NAME = "reconcile";

    public void reconcile(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            if (inputLine.hasArg("-more")) {
                showMorePatchHelp();
            } else {
                showPatchHelp();
                say("To see more on this topic, re-run this command with --help -more");
            }
            return;
        }
        boolean doAll = inputLine.hasArg(ALL);
        inputLine.removeSwitch(ALL);
        boolean isVerbose = inputLine.hasArg(VERBOSE);
        inputLine.removeSwitch(VERBOSE);
        boolean isTest = inputLine.hasArg(TEST);
        inputLine.removeSwitch(TEST);
        boolean isForce = inputLine.hasArg(FORCE);
        inputLine.removeSwitch(FORCE);
        String host = null;
        boolean hasHost = inputLine.hasArg(HOST);
        if (hasHost) {
            host = inputLine.getNextArgFor(HOST);
            inputLine.removeSwitchAndValue(HOST);
        }
        boolean doRollback = inputLine.hasArg(ROLLBACK);
        inputLine.removeSwitch(ROLLBACK);
        boolean resultSets = inputLine.hasArg(RESULT_SET);
        inputLine.removeSwitch(RESULT_SET);


        List<OA2ServiceTransaction> transactions;
        OA2ServiceTransaction transaction;
        if(isTest){
             say("** test mode enabled **");
         }
        if (doAll) {
            // Now need to get in the trenches... Lots of casts...
            // Goal is to not change anything but what is in this one class
            OA2TransactionKeys tKeys = (OA2TransactionKeys) getMapConverter().getKeys();
            OA2TStoreInterface<? extends OA2ServiceTransaction> tStore = (OA2TStoreInterface) getStore();
            // need dummy transaction to get fields.
            OA2ServiceTransaction dummy = tStore.create();
            if (doRollback) {
                transactions = (List<OA2ServiceTransaction>) tStore.search(tKeys.states(), ".*" + CLAIMS_SOURCES_STATE_KEY2 + ".*", true);
            } else {
                transactions = (List<OA2ServiceTransaction>) tStore.search(tKeys.states(), ".*" + dummy.CLAIMS_SOURCES_STATE_KEY + ".*", true);
            }
            if (hasHost) {
                // Have to filter the transactions
                List<OA2ServiceTransaction> filtered = new ArrayList<>();
                for (OA2ServiceTransaction oa2ServiceTransaction : transactions) {
                    if (oa2ServiceTransaction.getIdentifier().getUri().getHost().equals(host)) {
                        filtered.add(oa2ServiceTransaction);
                    }
                }
                transactions = filtered;
            }
            if (transactions.isEmpty()) {
                say("no transactions to process");
                return;
            }
            tStore.remove(dummy.getIdentifier()); // clean it up.
        } else {
            // do the one specified only.
            transaction = (OA2ServiceTransaction) findItem(inputLine);

            if (transaction == null) {
                say("sorry, no transaction specified.");
                return;
            }

            if (hasHost && !transaction.getIdentifier().getUri().getHost().equals(host)) {
                if (!readline("Host of the id is " + transaction.getIdentifier().getUri().getHost() + " but you specified a host of " + host + " Continue? (yes/no)").equals("yes")) {
                    say("aborting...");
                    return;
                }
            }
            transactions = new ArrayList<>();
            transactions.add(transaction);
        }
        int count = 0;
        List<Identifiable> unprocessed = new ArrayList<>();
        List<Identifiable> processed = new ArrayList<>();
        for (OA2ServiceTransaction oa2ServiceTransaction : transactions) {
            try {
                if (doRollback) {
                    if (!doRollback(oa2ServiceTransaction, isForce, isTest, isVerbose)) {
                        unprocessed.add(oa2ServiceTransaction);
                    } else {
                        processed.add(oa2ServiceTransaction);
                    }
                } else {
                    if (!doPatch(oa2ServiceTransaction, isForce, isTest, isVerbose)) {
                        unprocessed.add(oa2ServiceTransaction);
                    } else {
                        processed.add(oa2ServiceTransaction);
                    }
                }
                count++;
            } catch (Throwable t) {
                unprocessed.add(oa2ServiceTransaction);
                say("error " + oa2ServiceTransaction.getIdentifierString() + ": " + t.getMessage());
            }
        }
        if (resultSets) {
            getResultSets().put("bad", new RSRecord(unprocessed, null));
            getResultSets().put("good", new RSRecord(processed, null));
            say("result set created");
        }

        if (doAll) {
            if (unprocessed.size() == 0) {
                say("done! " + count + " transactions processed.");
            } else {
                say("done! " + count  + " transactions processed, " + unprocessed.size() + " skipped");
                if (isVerbose && !resultSets) {
                    say("Unprocessed transactions are");
                    for (Identifiable ttt : unprocessed) {
                        say(ttt.getIdentifierString());
                    }
                }
            }
        } else {
            if (unprocessed.size() == 1) {
                say("was unable to convert the transaction.");
            } else {
                say("done!");
            }
        }
       if(isTest){
           say("** test complete **");
       }
    }

    public String CLAIMS_SOURCES_STATE_KEY2 = "claims_sources2";

    protected boolean doPatch(OA2ServiceTransaction transaction,
                              boolean isForce,
                              boolean isTest,
                              boolean isVerbose) throws Exception {
        JSONArray array = new JSONArray();
        if (!transaction.getState().containsKey(transaction.CLAIMS_SOURCES_STATE_KEY)) {
            if (isVerbose) {
                say(transaction.getIdentifierString() + " --> skipped, no claims to convert to JSON");
            }
            return false;
        }
        if (!isForce && transaction.getState().containsKey(CLAIMS_SOURCES_STATE_KEY2)) {
            if (isVerbose) {
                say(transaction.getIdentifierString() + " --> skipped, claim source already converted. (Invoke with " + FORCE + " to override this.)");
            }
            return false;
        }
        try {
            for (ClaimSource claimSource : transaction.getClaimSources(null)) {
                array.add(ConfigtoCS.convert(claimSource).toJSON());
            }

        } catch (ClassCastException cce) {
            // In this case, the serialized claim sources cannot be deserialized under Java 8.
            // This implies that they were created in Java 11 and that the tool us being used out of sync
            // somehow with the Java version. Just tell them about it.
            if (isVerbose) {
                say(transaction.getIdentifierString() + " --> skipped, wrong version, cannot convert"  + ": " + cce.getMessage());
            }
            return false;
        }
        transaction.getState().put(CLAIMS_SOURCES_STATE_KEY2, array);

        if (isTest) {
            say(transaction.getIdentifierString() + " --> " + array);
        } else {
            getStore().save(transaction);
/*
            if (isVerbose) {
                say(transaction.getIdentifierString() + " --> done!");
            }
*/
        }
        return true;
    }

    protected boolean doRollback(OA2ServiceTransaction transaction,
                                 boolean isForce,
                                 boolean isTest,
                                 boolean isVerbose) throws Exception {
        if (!transaction.getState().containsKey(CLAIMS_SOURCES_STATE_KEY2)) {
            if (isVerbose) {
                say(transaction.getIdentifierString() + " --> skipped, no JSON claims source");
            }
            return false;
        }
        if (!isForce && transaction.getState().containsKey(transaction.CLAIMS_SOURCES_STATE_KEY)) {
            if (isVerbose) {
                say(transaction.getIdentifierString() + " --> already contains a claim source. Skipping. Invoke with " + FORCE + " to override this.");
            }
            return false;
        }
        JSONArray array = transaction.getState().getJSONArray(CLAIMS_SOURCES_STATE_KEY2);
        ArrayList<ClaimSource> claimSources = new ArrayList<>();
        for (int i = 0; i < array.size(); i++) {
            QDLStem stem = new QDLStem();
            claimSources.add(ConfigtoCS.convert(stem.fromJSON(array.getJSONObject(0)), null));
        }
        transaction.setClaimsSources(claimSources); // this will set the claims_sources as a serialized object.
        int byteCount = transaction.getState().getString(transaction.CLAIMS_SOURCES_STATE_KEY).length();
        if (isTest) {
            say(transaction.getIdentifierString() + " --> " + byteCount + " bytes.");
        } else {
            getStore().save(transaction);
            if (isVerbose) {
                say(transaction.getIdentifierString() + " -> "+ byteCount + " bytes written.");
            }
        }
        return true;
    }
}
