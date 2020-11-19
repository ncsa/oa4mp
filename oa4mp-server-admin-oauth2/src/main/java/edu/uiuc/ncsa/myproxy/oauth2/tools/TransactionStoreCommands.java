package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.DateUtils;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenImpl;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import net.sf.json.JSONObject;

import java.io.IOException;
import java.util.Date;

import static edu.uiuc.ncsa.security.core.util.StringUtils.pad2;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/16/20 at  3:16 PM
 */
public class TransactionStoreCommands extends StoreCommands2 {
    public TransactionStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

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
}
