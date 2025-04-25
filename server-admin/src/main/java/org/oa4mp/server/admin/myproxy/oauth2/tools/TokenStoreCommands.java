package org.oa4mp.server.admin.myproxy.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import org.oa4mp.server.admin.myproxy.oauth2.base.StoreCommands2;
import org.oa4mp.server.loader.oauth2.storage.tx.TXRecord;
import org.oa4mp.server.loader.oauth2.storage.tx.TXStore;

import java.io.IOException;
import java.util.Date;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  2:38 PM
 */
public class TokenStoreCommands extends StoreCommands2 {
    public TokenStoreCommands(MyLoggingFacade logger, String defaultIndent, Store store) throws Throwable {
        super(logger, defaultIndent, store);
    }

    public TokenStoreCommands(MyLoggingFacade logger, Store store) throws Throwable {
        super(logger, store);
    }

    @Override
    public String getName() {
        return "  tokens";
    }

    @Override
    public boolean update(Identifiable identifiable) throws IOException {
        say("update for all properties not implemented yet. You can still update individual properties");
        return false;
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

    public void get_by_parent(InputLine inputLine) throws Throwable {
        if(showHelp(inputLine)){
            say("get_by_parent index - get a simple list of the exchange records for a given transaction id");
            printIndexHelp(true);
            return;
        }
        Identifier parentID = findSingleton(inputLine).getIdentifier();
        List<? extends TXRecord> txRecords = getTXStore().getByParentID(parentID);
        int i = 0;
        for(TXRecord txRecord : txRecords){
            say((i++) + ". " + (new Date(txRecord.getExpiresAt())) + ": " + txRecord.getIdentifierString() ) ;
        }
        say(i + " exchange records found");
    }

    @Override
    public void bootstrap() throws Throwable {
        super.bootstrap();
        getHelpUtil().load("/help/token_help.xml");
    }

    @Override
    public void change_id(InputLine inputLine) throws Throwable {
        throw new UnsupportedOperationException("Not supported for exhange records.");
    }

    @Override
    protected int updateStorePermissions(Identifier newID, Identifier oldID, boolean copy) {
        throw new UnsupportedOperationException("Not supported for exhange records.");
    }
}
