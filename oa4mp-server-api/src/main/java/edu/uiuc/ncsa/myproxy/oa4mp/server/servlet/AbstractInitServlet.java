package edu.uiuc.ncsa.myproxy.oa4mp.server.servlet;

import edu.uiuc.ncsa.security.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.security.delegation.server.UnapprovedClientException;
import edu.uiuc.ncsa.security.delegation.server.request.AGRequest;
import edu.uiuc.ncsa.security.delegation.server.request.AGResponse;
import edu.uiuc.ncsa.security.delegation.servlet.TransactionState;
import edu.uiuc.ncsa.security.delegation.storage.Client;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 9/24/13 at  3:56 PM
 */
public abstract class AbstractInitServlet extends MyProxyDelegationServlet{

    /**
        * Default is to just call {@link #doDelegation(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)}
        * and return. You may over-ride this to do any pre or post -processing you require.
        *
        * @param httpServletRequest
        * @param httpServletResponse
        * @throws Throwable
        */
       @Override
       protected void doIt(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse) throws Throwable {
           doDelegation(httpServletRequest, httpServletResponse);
       }

       /**
        * Actual work call. This parses and returns the passed in parameters.
        *
        * @param req
        * @param resp
        * @return
        * @throws java.io.IOException
        * @throws javax.servlet.ServletException
        */
       protected ServiceTransaction doDelegation(HttpServletRequest req, HttpServletResponse resp) throws Throwable {
           Client client = getClient(req);
            ServiceTransaction transaction = newTransaction();
           transaction.setClient(client);
           try {
               String cid = "client=" + client.getIdentifier();
               info("2.a. Starting a new cert request: " + cid);
               checkClientApproval(client);

               AGResponse agResponse = (AGResponse) getAGI().process(new AGRequest(req, transaction));
               agResponse.setServiceTransaction(transaction);
               transaction = verifyAndGet(agResponse);
               getTransactionStore().save(transaction);
               info("Saved new transaction with id=" + transaction.getIdentifierString());

               Map<String, String> params = agResponse.getParameters();

               preprocess(new TransactionState(req, resp, params, transaction));
               debug("saved transaction for " + cid + ", trans id=" + transaction.getIdentifierString());

               agResponse.write(resp);
               info("2.b finished initial request for token =\"" + transaction.getIdentifierString() + "\".");

               postprocess(new IssuerTransactionState(req, resp, params, transaction, agResponse));
               return transaction;
           }
           catch (Throwable t) {
               if (t instanceof UnapprovedClientException ) {
                   warn("Unapproved client: " + client.getIdentifierString());
               }
               throw t;
           }
       }
}
