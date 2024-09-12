package org.oa4mp.server.api.util;

import edu.uiuc.ncsa.security.core.util.Iso8601;
import edu.uiuc.ncsa.security.core.util.MetaDebugUtil;
import org.oa4mp.delegation.server.ServiceTransaction;
import org.oa4mp.delegation.common.storage.clients.BaseClient;

import java.util.Date;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/25/21 at  2:47 PM
 */
public class ClientDebugUtil extends MetaDebugUtil {
    BaseClient client;

    public ClientDebugUtil(BaseClient client) {
        this.client = client;
    }

    public  void printIt(int level, Class callingClass, String message) {
        // Standard logging format is date host service: message
        if (level <= getDebugLevel()) {
            if(host == null || host.isEmpty()) {
                printIt((isPrintTS()?Iso8601.date2String(new Date()):"") + " "
                        + callingClass.getSimpleName() + " "
                        + toLabel(level) + ": [" + client.getIdentifierString() + "]" +
                        " " + message);
            }else{
                printIt((isPrintTS()?Iso8601.date2String(new Date()):"") + " " + host + " " + callingClass.getSimpleName() + " " + toLabel(level) + ": " + message);
            }
        }
    }


    public ServiceTransaction getTransaction() {
        return transaction;
    }

    public void setTransaction(ServiceTransaction transaction) {
        this.transaction = transaction;
    }

    ServiceTransaction transaction = null;
    public boolean hasTransaction(){
        return transaction != null;
    }
    String tID = null;
    String tID(){
      if(tID == null){
            String p = transaction.getIdentifier().getUri().getPath();
            tID = p.substring(p.lastIndexOf("/"));
      }
      return tID;
    }

    public BaseClient getClient() {
        return client;
    }

    public void setClient(BaseClient client) {
        this.client = client;
    }
}
