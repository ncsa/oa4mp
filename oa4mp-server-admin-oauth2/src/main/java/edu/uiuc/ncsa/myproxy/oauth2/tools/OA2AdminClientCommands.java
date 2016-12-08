package edu.uiuc.ncsa.myproxy.oauth2.tools;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.testing.BaseClientStoreCommands;
import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApprovalStore;
import org.apache.commons.codec.digest.DigestUtils;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/8/16 at  12:34 PM
 */
public class OA2AdminClientCommands extends BaseClientStoreCommands {
    public OA2AdminClientCommands(MyLoggingFacade logger, String defaultIndent, Store clientStore, ClientApprovalStore clientApprovalStore) {
        super(logger, defaultIndent, clientStore, clientApprovalStore);
    }

    @Override
       public String getName() {
           return "  admins";
       }


    @Override
      protected void longFormat(Identifiable identifiable) {
        super.longFormat(identifiable);
          AdminClient client = (AdminClient) identifiable;
          sayi("issuer=" + client.getIssuer());
          sayi("vo=" + client.getVirtualOrganization());
      }

    @Override
       public void extraUpdates(Identifiable identifiable) {
        AdminClient client = (AdminClient) identifiable;
           String secret = client.getSecret();
           String input;
           boolean askForSecret = true;


           while (askForSecret) {
               input = getInput("enter a new secret or return to skip.", secret);
               if (isEmpty(input)) {
                   sayi("Nothing entered. Client secret entry skipped.");
                   break;
               }
               if (input.equals(secret)) {
                   sayi(" Client secret entry skipped.");
                   break;
               }
               // input is not empty.
               secret = DigestUtils.shaHex(input);
               client.setSecret(secret);
               askForSecret = false;
           }
        String issuer = getInput("Give the issuer", client.getIssuer());
        if(!isEmpty(issuer)){
            client.setIssuer(issuer);
        }
        String vo = getInput("Give the VO", client.getVirtualOrganization());
        if(!isEmpty(vo)){
            client.setVirtualOrganization(vo);
        }

       }
}
