package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClient;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.adminClient.AdminClientStore;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.DebugUtil;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2ATException;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants.CLIENT_SECRET;

/**
 * This class has the machinery for processing the various types of
 * Authorization for a servlet. <br/><br/>
 *
 * <p>Created by Jeff Gaynor<br>
 * on 7/24/21 at  5:58 AM
 */
/*
  This class has the
 */
public abstract class MultiAuthServlet extends MyProxyDelegationServlet {
    /**
       * This finds the client identifier either as a parameter or in the authorization header and uses
       * that to get the client. It will also check if the client has been approved and throw an
       * exception if that is not the case. You must separately check the secret as needed
       * using {@link #getClientSecret(HttpServletRequest)} then {@link #verifyClientSecret(OA2Client, String)}.
       *
       * @param request
       * @return
       */
      @Override
      public Client getClient(HttpServletRequest request) {
          // Check is this is in the headers. If not, fall through to checking parameters.
          OA2Client client = null;
          Identifier paramID = OA2HeaderUtils.getIDFromParameters(request);
          Identifier headerID = null;
          try {
              headerID = OA2HeaderUtils.getIDFromHeaders(request);
          } catch (UnsupportedEncodingException e) {
              throw new NFWException("Error: internal use of UTF-8 encoding failed");
          } catch (Throwable tt) {
              ServletDebugUtil.trace(this.getClass(), "Got an exception checking for the header. " +
                      "This is usually benign:\"" + tt.getMessage() + "\"");
          }
          // we have to check that if we get both of these they refer to the same client, so someone
          // cannot hijack the session
          if (paramID == null) {
              if (headerID == null) {
                  throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no client identifier given");
              }
              client = (OA2Client) getClient(headerID);
          } else {
              if (headerID == null) {
                  client = (OA2Client) getClient(paramID);
              } else {
                  if (!paramID.equals(headerID)) {
                      throw new OA2ATException(OA2Errors.INVALID_REQUEST, "too many client identifiers");
                  }
                  client = (OA2Client) getClient(headerID); // doesn't matter which id we use since they are equal.
              }
          }
         // Approval is checked in getClient
        //  checkClientApproval(client);
          return client;
      }

      public void verifyClientSecret(OA2Client client, String rawSecret) {
          ClientUtils.verifyClientSecret(client, rawSecret, true);
      }

    protected String getClientSecret(HttpServletRequest request) {
        return ClientUtils.getClientSecret(request, getFirstParameterValue(request, CLIENT_SECRET));
    }
    public AdminClient getAdminClient(HttpServletRequest request) {
        // Check is this is in the headers. If not, fall through to checking parameters.
        AdminClient adminClient = null;
        Identifier paramID = OA2HeaderUtils.getIDFromParameters(request);
        Identifier headerID = null;
        try {
            headerID = OA2HeaderUtils.getIDFromHeaders(request);
        } catch (UnsupportedEncodingException e) {
            throw new NFWException("Error: internal use of UTF-8 encoding failed");
        } catch (Throwable tt) {
            ServletDebugUtil.trace(this.getClass(), "Got an exception checking for the header. " +
                    "This is usually benign:\"" + tt.getMessage() + "\"");
        }
        // we have to check that if we get both of these they refer to the same client, so someone
        // cannot hijack the session
        if (paramID == null) {
            if (headerID == null) {
                throw new OA2ATException(OA2Errors.INVALID_REQUEST, "no client identifier given");
            }
            adminClient =  getAdminClient(headerID);
        } else {
            if (headerID == null) {
                adminClient =  getAdminClient(paramID);
            } else {
                if (!paramID.equals(headerID)) {
                    throw new OA2ATException(OA2Errors.INVALID_REQUEST, "too many client identifiers", adminClient);
                }
                adminClient =  getAdminClient(headerID); // doesn't matter which id we use since they are equal.
            }
        }
        return adminClient;
    }
    public AdminClient getAdminClient(Identifier identifier) {
        AdminClientStore<AdminClient> store = getServiceEnvironment().getAdminClientStore();;
        if (identifier == null) {
            throw new UnknownClientException("no client id");
        }
        AdminClient c = store.get(identifier);
        if (c == null) {
            if (store.size() == 0) {
                // This tries to show if, perhaps, the wrong store wa loaded by printing out a little information about it.
                DebugUtil.trace(this,"ADMIN CLIENT STORE HAS NO ENTRIES!");
                DebugUtil.trace(this, "client name is " + store.getClass().getSimpleName());
                DebugUtil.trace(this, "client store is a " + store);
            }
            String ww = "Unknown admin client: \"" + identifier + "\"  cannot be found.";
            warn(ww + " admin client store is " + store);
            throw new UnknownClientException(ww + "  Is the value in the client config correct?", identifier);
        }
        checkClientApproval(c); // All approvals are in the same store, so this works.
        return c;
    }
}
