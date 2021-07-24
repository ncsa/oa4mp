package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.delegation.storage.Client;
import edu.uiuc.ncsa.security.oauth_2_0.OA2ATException;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Errors;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;

import static edu.uiuc.ncsa.security.oauth_2_0.OA2Constants.CLIENT_SECRET;

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
       * exception if that is not the case. You must separately check the secret as needed.
       *
       * @param request
       * @return
       */
      @Override
      public Client getClient(HttpServletRequest request) {
          // Check is this is in the headers. If not, fall through to checking parameters.
          OA2Client client = null;
          Identifier paramID = HeaderUtils.getIDFromParameters(request);
          Identifier headerID = null;
          try {
              headerID = HeaderUtils.getIDFromHeaders(request);
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

          checkClientApproval(client);


          return client;
      }

      public void verifyClientSecret(OA2Client client, String rawSecret) {
          ClientUtils.verifyClientSecret(client, rawSecret, true);
      }

    protected String getClientSecret(HttpServletRequest request) {
        return ClientUtils.getClientSecret(request, getFirstParameterValue(request, CLIENT_SECRET));
    }

}
