package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXStore;
import edu.uiuc.ncsa.myproxy.oauth2.base.StoreCommands2;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.InputLine;

import java.io.IOException;
import java.util.Date;
import java.util.List;

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
        return "  tokens";
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

    protected TXStore<? extends TXRecord> getTXStore(){
        return (TXStore<? extends TXRecord>) getStore();
    }

    public void get_by_parent(InputLine inputLine){
        if(showHelp(inputLine)){
            say("get_by_parent id - get a simple list of the exchange records for a given transaction id");
            return;
        }
        String lastArg = inputLine.getLastArg();

        Identifier parentID = BasicIdentifier.newID(lastArg);
        List<? extends TXRecord> txRecords = getTXStore().getByParentID(parentID);
        int i = 0;
        for(TXRecord txRecord : txRecords){
            say((i++) + ". " + (new Date(txRecord.getExpiresAt())) + ": " + txRecord.getIdentifierString() ) ;
        }
        say(i + " exchange records found");
    }
}
