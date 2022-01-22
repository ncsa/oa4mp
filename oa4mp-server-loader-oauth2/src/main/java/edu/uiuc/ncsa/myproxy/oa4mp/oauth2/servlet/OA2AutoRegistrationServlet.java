package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.server.util.NewClientEvent;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientApproval;
import edu.uiuc.ncsa.security.delegation.storage.Client;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/28/11 at  1:20 PM
 */
// Boiler-plated over from OAuth 1 so there are no screwy dependencies.
public class OA2AutoRegistrationServlet extends OA2RegistrationServlet{
    @Override
     protected Client addNewClient(HttpServletRequest request, HttpServletResponse response) throws Throwable{
         Client client = super.addNewClient(request, response);
         if(client != null){
             approveClient(client.getIdentifier(), "auto-approver");
         }
         fireNewClientEvent(new NewClientEvent(this,client));
         return client;
     }

     /**
      * This will approve a client. Supply the approver and client
      *
      * @param clientIdentifier
      * @param approver
      */
     public static void approveClient(Identifier clientIdentifier, String approver) throws IOException {
         ClientApproval clientApproval = getServiceEnvironment().getClientApprovalStore().get(clientIdentifier);
         if (approver == null) {
             approver = ""; // so you don't get something ugly in the backend.
         }
         clientApproval.setApprover(approver);
         clientApproval.setApproved(true);
         clientApproval.setStatus(ClientApproval.Status.APPROVED);
         getServiceEnvironment().getClientApprovalStore().save(clientApproval);
     }
}
