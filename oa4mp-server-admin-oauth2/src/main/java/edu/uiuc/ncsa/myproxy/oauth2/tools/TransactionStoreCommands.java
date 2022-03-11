package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.*;
import edu.uiuc.ncsa.security.delegation.storage.TransactionStore;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenImpl;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;
import org.apache.commons.codec.binary.Base64;

import java.io.*;
import java.net.URI;
import java.util.Date;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import static edu.uiuc.ncsa.security.core.util.StringUtils.pad2;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/16/20 at  3:16 PM
 */
public class TransactionStoreCommands extends StoreCommands2 {
    public TransactionStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store, TXStore txStore) {
        super(logger, defaultIndent, store);
        this.txStore = txStore;
    }

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
       if(!inputLine.hasArg(CL_INPUT_FILE_FLAG)){
           say("sorry, but you must specify a file");
           return;
       }
        String f = inputLine.getNextArgFor(CL_INPUT_FILE_FLAG);
       inputLine.removeSwitchAndValue(CL_OUTPUT_FILE_FLAG);
       OA2ServiceTransaction t = (OA2ServiceTransaction) findItem(inputLine);
       if(t == null){
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
        if(saveFile){
            try {
                FileUtil.writeStringToFile(f, out.toString());
                say("saved QDL state to '" + f + "'");
            } catch (Throwable e) {
                say("saving to '" + f + " failed:" + e.getMessage());
                if(isVerbose() && isPrintOuput()){
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
}
