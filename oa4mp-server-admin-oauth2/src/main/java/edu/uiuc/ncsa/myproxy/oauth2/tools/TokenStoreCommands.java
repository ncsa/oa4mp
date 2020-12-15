package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.server.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;

import java.io.IOException;
import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  2:38 PM
 */
public class TokenStoreCommands extends StoreCommands2 {
    public TokenStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store) {
        super(logger, defaultIndent, store);
    }

    public TokenStoreCommands(MyLoggingFacade logger, Store store) {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "tokens";
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
        TXRecord txRecord = (TXRecord)identifiable;
        Date issuedAt = new Date();
        Date expiresAt= new Date();
        issuedAt.setTime(txRecord.getIssuedAt());
        expiresAt.setTime( txRecord.getExpiresAt());
        String r = txRecord.getIdentifierString() + "\n" + INDENT + "  parent= " + txRecord.getParentID() +
                "\n" + INDENT + "  issued at " + issuedAt+ ", expires at " + expiresAt;
        return r;
    }
}
