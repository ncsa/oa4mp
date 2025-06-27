package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.cache.Cleanup;
import edu.uiuc.ncsa.security.core.cache.LockingCleanup;
import edu.uiuc.ncsa.security.core.exceptions.TransactionNotFoundException;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.storage.cli.FoundIdentifiables;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;
import org.oa4mp.delegation.common.storage.TransactionStore;
import org.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import org.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import org.oa4mp.delegation.common.token.impl.TokenImpl;
import org.oa4mp.server.admin.oauth2.base.OA4MPStoreCommands;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.servlet.TokenExchangeRecordRetentionPolicy;
import org.oa4mp.server.loader.oauth2.storage.RefreshTokenRetentionPolicy;
import org.oa4mp.server.loader.oauth2.storage.RefreshTokenStore;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2ServiceTransaction;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2TStoreInterface;
import org.oa4mp.server.loader.oauth2.storage.transactions.OA2TransactionKeys;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecordSerializationKeys;
import org.oa4mp.server.loader.oauth2.storage.tx.TXStore;

import java.io.*;
import java.net.URI;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static edu.uiuc.ncsa.security.core.cache.LockingCleanup.lockID;
import static edu.uiuc.ncsa.security.core.util.StringUtils.*;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/16/20 at  3:16 PM
 */
public class TransactionStoreCommands extends OA4MPStoreCommands {
    public TransactionStoreCommands(MyLoggingFacade logger, String defaultIndent, OA2SE oa2se) throws Throwable {
        super(logger, defaultIndent, oa2se.getTransactionStore());
        this.oa2se = oa2se;
        this.txStore = oa2se.getTxStore();
    }

    OA2SE oa2se;

    public TXStore getTxStore() {
        return txStore;
    }

    TXStore<? extends TXRecord> txStore;

    public TransactionStoreCommands(MyLoggingFacade logger, Store store) throws Throwable {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "transactions";
    }

    @Override
    public boolean update(Identifiable identifiable) throws IOException {
        say("update for all properties not implemented yet. You can still update individual properties");
        return false;
    }


    @Override
    protected String format(Identifiable identifiable) {
        OA2ServiceTransaction t = (OA2ServiceTransaction) identifiable;
        return "id : " + t.getIdentifierString() + " | " +
                "auth time : " + t.getAuthTime();
    }

    public void tokens(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showExpHelp();
            return;
        }
        FoundIdentifiables foundIdentifiables = findItem(inputLine);

        int width = 30;
        String stile = " | ";
        String plus = "-+-";
        boolean showAG = true;
        boolean showAT = true;
        boolean showRT = true;
        if (0 < inputLine.getArgCount()) {
            showAG = inputLine.hasArg("-ag");
            showAT = inputLine.hasArg("-at");
            showRT = inputLine.hasArg("-rt");
            if ((!showAG && !showAT && !showRT)) {
                say("unrecognized option(s). ");
                return;
            }
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
        String hLine = StringUtils.hLine("-",15)
                + plus
                + hLine("-",3)
                + plus
                + hLine("-",7)
                + plus
                + hLine("-",width)
                + plus
                + hLine("-",width)
                + plus
                + hLine("-",width);
        say(hLine);
        for (Identifiable identifiable : foundIdentifiables) {
            OA2ServiceTransaction t = (OA2ServiceTransaction) identifiable;
if(1 < foundIdentifiables.size()){
    say(t.getIdentifierString());
    say(hLine);
}
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
                say(hLine);
        }// end loop
//
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
        say("tokens [-at | -rt | -ag] index");
        sayi("Show information about tokens such as if its a jwt, validity, issue time, expiration times, etc. in human readable format");
        sayi("No arguments means show everything. Flags are");
        sayi("-ag = authorization grant");
        sayi("-at = access token");
        sayi("-rt = refresh token");

        sayi("If the tokens are not set, that is shown too with a set of ----");
        sayi("An asterisk before the token name means that that token has expired.");
        printIndexHelp(false);
    }

    public void claims(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showClaimsHelp();
            return;
        }

        FoundIdentifiables identifiables = findItem(inputLine);
        for(Identifiable identifiable : identifiables) {
            OA2ServiceTransaction t = (OA2ServiceTransaction) identifiable;
            if(1 < identifiables.size()){
                say(t.getIdentifierString());
                say(hLine("-", t.getIdentifierString().length()));
            }
            if (t.getUserMetaData() != null) {
                say(t.getUserMetaData().toString(1));
            } else {
                say("(no claims found)");
            }
            if(1 < identifiables.size()){
                say();
            }
        }
    }

    private void showClaimsHelp() {
        say("claims index");
        sayi("Show the claims associated with this transaction. These are mostly used to create the id token");
        printIndexHelp(false);
    }

    public static final String LS_AT_FLAG = "-at";
    public static final String LS_RT_FLAG = "-rt";
    public static final String LS_IDT_FLAG = "-idt";

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
        OA2ServiceTransaction serviceTransaction = null;
        try {
            serviceTransaction = (OA2ServiceTransaction) ((TransactionStore) getStore()).get(at);
        } catch (TransactionNotFoundException tnf) {

        }
        if (serviceTransaction != null) {
            return serviceTransaction.getIdentifier();
        }
        // try to get it from the TXStore
        TXRecord txRecord = (TXRecord) getTxStore().get(BasicIdentifier.newID(rawAT));
        if (txRecord != null) {
            return txRecord.getParentID();
        }
        return null;
    }

    protected Identifier getIDByIDT(InputLine inputLine) {
        OA2TransactionKeys tKeys = (OA2TransactionKeys) getMapConverter().getKeys();
        TXRecordSerializationKeys txKeys = (TXRecordSerializationKeys) getTxStore().getMapConverter().getKeys();
        String rawIDT = inputLine.getNextArgFor(LS_IDT_FLAG);
        OA2ServiceTransaction serviceTransaction = null;

        List tStoreList = getStore().search(tKeys.idTokenIdentifier(), rawIDT, false);
        if (!tStoreList.isEmpty()) {
            serviceTransaction = (OA2ServiceTransaction) tStoreList.get(0);
            return serviceTransaction.getIdentifier();
        }
        // So not found, implies it reside in a TX record someplace. Find it.
        List txStoreList = getTxStore().search(txKeys.token(), rawIDT, false);
        if (!txStoreList.isEmpty()) {
            TXRecord txRecord = (TXRecord) txStoreList.get(0);
            return txRecord.getParentID();
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
        OA2ServiceTransaction serviceTransaction = null;
        try {
            serviceTransaction = ((RefreshTokenStore) getStore()).get(rt);
        } catch (TransactionNotFoundException tfn) {

        }
        if (serviceTransaction != null) {
            return serviceTransaction.getIdentifier();
        }
        // try to get it from the TXStore
        TXRecord txRecord = (TXRecord) getTxStore().get(BasicIdentifier.newID(rawRT));
        if (txRecord != null) {
            return txRecord.getParentID();
        }
        return null;
    }

    @Override
    public void ls(InputLine inputLine) throws Throwable {
        // strategy is to fund the actual id and use that to construct the right input line
        // and pass it off to the super function so we don't have to re-invent the wheel.
        if (showHelp(inputLine)) {
            showLSHelp();
            say("For transaction stores, you may also specify listing by using the access, identity or refresh token:");
            say("ls [" + LS_AT_FLAG + " | " + LS_IDT_FLAG + " | " + LS_RT_FLAG + " token]");
            say("Note that other switches, such as " + VERBOSE_COMMAND + " work as well.");
            say("See also: set_id, which takes flags in this component.");
            return;
        }
        Identifier identifier = null;
        boolean getByToken = inputLine.hasArg(LS_AT_FLAG, LS_RT_FLAG, LS_IDT_FLAG);
        if (getByToken) {
            identifier = getTokenByType(inputLine);
            if (identifier == null) {
                String tokenType = "(unknown)";
                if (inputLine.hasArg(LS_AT_FLAG)) {
                    tokenType = "access";
                }

                if (inputLine.hasArg(LS_RT_FLAG)) {
                    tokenType = "refresh";
                }
                if (inputLine.hasArg(LS_IDT_FLAG)) {
                    tokenType = "identity";
                }
                say("Sorry but no such " + tokenType + " token found.");
                return;
            }
            inputLine.removeSwitchAndValue(LS_AT_FLAG, LS_RT_FLAG, LS_IDT_FLAG);
            inputLine.appendArg("/" + identifier);
        }
        List<Identifier> oldIDs = null;
        if (getByToken) {
            // zero it out so even if they set an id, they can still search by id token.
            oldIDs = getID();
            setID(null);
        }
        try {
            super.ls(inputLine);
        } catch (Throwable t) {
            say("uh-oh... there wasn an error:" + t.getMessage());
            return;
        }
        // set it back.
        if (getByToken) {
            setID(oldIDs);
        }
    }

    protected Identifier getTokenByType(InputLine inputLine) {
        Identifier identifier = null;
        if (inputLine.hasArg(LS_AT_FLAG)) {
            identifier = getIDbyAT(inputLine);
        }

        if (inputLine.hasArg(LS_RT_FLAG)) {
            identifier = getIDByRT(inputLine);
        }
        if (inputLine.hasArg(LS_IDT_FLAG)) {
            identifier = getIDByIDT(inputLine);
        }
        return identifier;
    }


    // Fix https://github.com/ncsa/oa4mp/issues/245
    @Override
    public void set_id(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set_id [" + LS_AT_FLAG + " | " + LS_IDT_FLAG + " | " + LS_RT_FLAG + "] token]");
            say(LS_AT_FLAG + " search as the access token");
            say(LS_IDT_FLAG + "search as the id token");
            say(LS_RT_FLAG + "search as the refresh token");
            say("Otherwise, try to find the identifier of the record for the given type");
            say("If only the token given, that is the identifier and use that.");
            say("This will also snoop through exchange records and resolve tokens off of those.");
            say("E.g.");
            say("set_id oa4mp:/rfc7523/transaction/9373267");
            say("would set the token identifier");
            say("set_id " + LS_AT_FLAG + " oa4mp:/790064?type=accessToken&ts=1745336738943&version=v2.0&lifetime=900000");
            say("would look up the transaction by the given (in this case) access token, then set the identifier");
            say("to the found transactions id.");

        }
        // Boilerplated off the ls function.
        Identifier identifier = null;
        boolean getByToken = inputLine.hasArg(LS_AT_FLAG, LS_RT_FLAG, LS_IDT_FLAG);
        if (getByToken) {
            identifier = getTokenByType(inputLine);
            if (identifier == null) {
                String tokenType = "(unknown)";
                if (inputLine.hasArg(LS_AT_FLAG)) {
                    tokenType = "access";
                }

                if (inputLine.hasArg(LS_RT_FLAG)) {
                    tokenType = "refresh";
                }
                if (inputLine.hasArg(LS_IDT_FLAG)) {
                    tokenType = "identity";
                }
                say("Sorry but no such " + tokenType + " token found.");
            } else {
                List<Identifier> x = new ArrayList<>();
                x.add(identifier);
                setID(x);
            }
        } else {
            super.set_id(inputLine);
        }
    }

    public void set_qdl_state(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("set_qdl_state " + CL_INPUT_FILE_FLAG + " file_path index");
            say("replace the qdl state in the transaction with the contents of the file.");
            say("Note that the file is XML and will be converted as needed.");
            printIndexHelp(false);
            say("See also: show_qdl_state");
            return;
        }
        FoundIdentifiables foundIdentifiables = findItem(inputLine);
        if (!inputLine.hasArg(CL_INPUT_FILE_FLAG)) {
            say("sorry, but you must specify a file");
            return;
        }
        String f = inputLine.getNextArgFor(CL_INPUT_FILE_FLAG);
        inputLine.removeSwitchAndValue(CL_OUTPUT_FILE_FLAG);

        String rawFile = FileUtil.readFileAsString(f);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        GZIPOutputStream gzipOutputStream = new GZIPOutputStream(baos);
        gzipOutputStream.write(rawFile.getBytes("UTF-8"));
        gzipOutputStream.flush();
        gzipOutputStream.close();
        String encoded = Base64.encodeBase64URLSafeString(baos.toByteArray());
        for(Identifiable i : foundIdentifiables) {
            OA2ServiceTransaction t = (OA2ServiceTransaction) i;
            t.setScriptState(encoded);
        }
        say(foundIdentifiables.size() + " processed, done!");
    }

    public void show_qdl_state(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("show_qdl_state [" + LS_AT_FLAG + "|" + LS_RT_FLAG + " " + CL_OUTPUT_FILE_FLAG + " file_path] index");
            say("Find the given transaction, get the current state from QDL and decode it.");
            say(CL_OUTPUT_FILE_FLAG + " file_path = You may optionally save it to a file.");
            printIndexHelp(false);
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

        OA2ServiceTransaction transaction = (OA2ServiceTransaction) findSingleton(inputLine, "transaction not found");
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

        say(format(serviceTransaction));
    }

    public void get_by_proxy_id(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("get_by_proxy_id proxy_id - get a transaction by its proxy_id");
            return;
        }
        if (!(getStore() instanceof OA2TStoreInterface)) {
            say("wrong store type");
            return;
        }
        OA2TStoreInterface tStoreInterface = (OA2TStoreInterface) getStore();
        String proxyID = inputLine.getLastArg();
        OA2ServiceTransaction serviceTransaction = tStoreInterface.getByProxyID(BasicIdentifier.newID(proxyID));

        if (serviceTransaction == null) {
            say("no transaction found");
            return;
        }

        say(format(serviceTransaction));
    }

    /**
     * Does a basic garbage collection check against the {@link RefreshTokenRetentionPolicy}.
     * This component does not have access to the full service environment so cannot quite
     * reconstruct the exact call: It will assume safeGC mode is set to false.
     *
     * @param inputLine
     * @throws Exception
     */
    public void gc_check(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            say("gc_check index = check if the transaction would get garbage collected");
            say("                      in the current environment.");
            say("Note that the check is done assuming safe GC mode on the server is false.");
            printIndexHelp(false);
            return;
        }
        FoundIdentifiables identifiables = findItem(inputLine);
        if (identifiables == null) {
            say("Sorry, transaction not found");
            return;
        }
        RefreshTokenRetentionPolicy refreshTokenRetentionPolicy =
                new RefreshTokenRetentionPolicy((RefreshTokenStore) getStore(), getTxStore(), "", false);
        String retainTitle = "retain?";
        int retainTitleWidth = retainTitle.length();
        String idTitle = "id";
        say(retainTitle + " | " + idTitle);
        for (Identifiable identifiable : identifiables) {
            String out = StringUtils.center(refreshTokenRetentionPolicy.retain(identifiable.getIdentifier(), identifiable)?"y":"n", retainTitleWidth);
            out = out + " | " + identifiable.getIdentifier();
            say(out);
        }
    }

    public static String GC_SAFE_MODE_FLAG = "-safe_gc";
    public static String GC_TEST_FLAG = "-test";
    public static String GC_SIZE_FLAG = "-size";
    public static String GC_FILE_FLAG = "-file";

    public void gc_run(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("gc_run [" +
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
        if (!testMode) {
            if (!readline("Are you SURE? (Yes/no)").equals("Yes")) {
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

        txRecordCleanup.setStore(getTxStore());
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


    public void gc_lock(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("gc_lock [-rm | ? | -alarms]");
            say("-set [T|TX|all] - lock the transaction and TX stores");
            say("-rm [T|TX|all] - remove given locks");
            say("? - report if stores are locked.");
            say("-alarms - show configured alarms");
            return;
        }
        boolean hasSet = inputLine.hasArg("-set");
        if (hasSet) {
            String arg = inputLine.getNextArgFor("-set");
            inputLine.removeSwitchAndValue("-set");
            boolean lockT = false;
            boolean lockTX = false;
            switch (arg) {
                case "T":
                    lockT = true;
                    break;
                case "TX":
                    lockTX = true;
                    break;
                case "all":
                    lockTX = true;
                    lockT = true;
                    break;
                default:
                    say("sorry, unknown option to set lock:\"" + arg + "\"");
                    return;
            }
            if (lockT) {
                Identifiable tLock = getStore().create();
                tLock.setIdentifier(lockID);
                getStore().save(tLock);
                say("transaction store locked");
            }

            if (lockTX) {
                Identifiable tLock = getTxStore().create();
                tLock.setIdentifier(lockID);
                getTxStore().save(tLock);
                say("TX store locked");
            }
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
        if (inputLine.hasArg("-rm")) {
            boolean unlockT = false;
            boolean unlockTX = false;
            String arg = inputLine.getNextArgFor("-rm");
            switch (arg) {
                case "T":
                    unlockT = true;
                    break;
                case "TX":
                    unlockTX = true;
                    break;
                case "all":
                    unlockTX = true;
                    unlockT = true;
                    break;
                default:
                    say("sorry, unknown option to unlock:\"" + arg + "\"");
                    return;
            }

            say("removing locks...");
            if (unlockT) {
                boolean t = null == getStore().remove(lockID);
                say((t ? "did not remove" : "removed") + " transaction store lock");
            }
            if (unlockTX) {
                boolean tx = null == getTxStore().remove(lockID);
                say((tx ? "did not remove" : "removed") + " TX store store lock");
            }
            return;
        }
        // Default case.
        say("transactions locked? " + getStore().containsKey(lockID));
        say("TX store locked? " + getTxStore().containsKey(lockID));
        return;
    }

    @Override
    public void bootstrap(InputLine inputLine) throws Throwable {
        super.bootstrap(inputLine);
    }

    @Override
    protected void initHelp() throws Throwable {
        super.initHelp();
        getHelpUtil().load("/help/transaction_help.xml");
    }

    /**
     * Removes all transactions and TX records for a given client
     *
     * @param inputLine
     * @throws Exception
     */

    // Fix https://github.com/ncsa/oa4mp/issues/225
    public void rm_by_client_id(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("rm_by_client_id client_id - remove all current transactions for the given client.");
            say("client_id = the unique identifier for a client");
            say("Note that this cannot be undone and any operations for clients on these");
            say("will start failing instantly. This kills all pending transactions for the client");
            say("and is normally only used if there is a security breach that requires it shutting the client off asap.");
            return;
        }
        if (!inputLine.hasArgs()) {
            say("missing client id.");
            return;
        }
        OA2TStoreInterface<? extends OA2ServiceTransaction> tStore = (OA2TStoreInterface<? extends OA2ServiceTransaction>) getStore();
        Identifier clientID = BasicIdentifier.newID(inputLine.getLastArg());
        List<Identifier> ids = tStore.getByClientID(clientID);
        if (ids.isEmpty()) {
            say("no transactions found for client id: " + clientID);
            //    return;
        }
        tStore.removeByID(ids);
        say("removed " + ids.size() + " transactions");
        long counter = 0;
        // now for tokens
        for (Identifier id : ids) {
            List<Identifier> txValues = getTxStore().getIDsByParentID(id);
            counter = counter + txValues.size();
            getTxStore().removeByID(txValues);
        }
        if (counter == 0) {
            say("no refresh/exchange records found");
        } else {
            say("removed " + counter + "  exchange/refresh records");
        }
        say("total items removed from all stores:" + (counter + ids.size()));
    }

    /**
     * Print stats about the number of outstanding transactions and exchange/refresh records.
     *
     * @param inputLine
     * @throws Exception
     */
    // Fix https://github.com/ncsa/oa4mp/issues/225
    public void stats(InputLine inputLine) throws Exception {
        if (showHelp(inputLine)) {
            say("stats [-client client_id] [-v] [-top n] = prints report on the number of tokens currently help by this client.");
            say("-client client_id = the unique identifier for a client");
            say("-v = verbose mode for -client. Print numbers of refresh/exchanges per id, otherwise print a single number");
            say("-top n = n is an integer. Print the top n most used client ids with counts and percents");
            return;
        }
        if (!inputLine.hasArgs()) {
            say("no arguments");
            return;
        }
        boolean isTop = inputLine.hasArg("-top");
        int n = 0;
        String rawN = "";
        if (isTop) {
            try {
                rawN = inputLine.getNextArgFor("-top");
                n = Integer.parseInt(rawN);
                if (n <= 0) {
                    say("top n should be positive");
                    return;
                }
                inputLine.removeSwitchAndValue("-top");
            } catch (Throwable t) {
                n = 10;
                say("sorry, but \"" + rawN + "\" did not parse as a number");

            }
        }
        OA2TStoreInterface<? extends OA2ServiceTransaction> tStore = (OA2TStoreInterface<? extends OA2ServiceTransaction>) getStore();

        if (isTop) {
            List<Identifier> ids = tStore.getAllClientID();
            long total = ids.size();
            if (total == 0) {
                say("no transactions found");
                return;
            }
            HashMap<Identifier, Long> counts = new HashMap<>();
            for (Identifier id : ids) {
                if (counts.containsKey(id)) {
                    counts.put(id, counts.get(id) + 1);
                } else {
                    counts.put(id, 0L);
                }
            }
            List<Map.Entry<Identifier, Long>> list = new ArrayList<>(counts.entrySet());
            list.sort(Map.Entry.comparingByValue());
            Collections.reverse(list); // from highest to lowest
            Map<Identifier, Long> sortedCounts = new LinkedHashMap<>();
            for (Map.Entry<Identifier, Long> entry : list) {
                sortedCounts.put(entry.getKey(), entry.getValue());
            }
            // finally
            int max = Math.min(n, sortedCounts.size());
            int i = 0;
            int fieldWidth = 10;
            say(center("count", fieldWidth) + "|" + center("percent", fieldWidth) + "|  client id");
            say("----------+----------+------------------------------");
            for (Identifier id : sortedCounts.keySet()) {
                if (max < i++) {
                    break;
                }
                say(center(sortedCounts.get(id).toString(), fieldWidth) + "|" + center(String.format("%.3f", ((100.00 * sortedCounts.get(id)) / total)) + "%", fieldWidth) + "|  " + id);
            }
            say("total transactions:" + total);
            return;
        }
        boolean isVerbose = inputLine.hasArg("-v");
        inputLine.removeSwitch("-v");
        Identifier clientID = BasicIdentifier.newID(inputLine.getLastArg());
        List<Identifier> ids = tStore.getByClientID(clientID);

        if (ids.isEmpty()) {
            say("no transactions found for client id: " + clientID);
            return;
        }
        say(ids.size() + " base transaction count");
        long counter = 0;
        // now for tokens
        for (Identifier id : ids) {
            List<Identifier> txValues = getTxStore().getByParentID(id);
            counter = counter + txValues.size();
            if (isVerbose) {
                say(StringUtils.pad(String.valueOf(txValues.size()), 10) + " | " + id);
            }
        }
        if (counter == 0) {
            say("no refresh/exchange records found");
        } else {
            say(counter + " total exchange/refresh records");
        }
        say("total transactions and other records:" + (counter + ids.size()));
    }

    @Override
    public void change_id(InputLine inputLine) throws Throwable {
        say("Changing transaction ids is not supported at this time.");
    }

    /*
        Typically there there are no such records and nobody should change the id of one of these.
         */
    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        throw new UnsupportedOperationException("Not supported.");
    }
}
