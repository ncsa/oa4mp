package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2Errors;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2GeneralError;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.MyOtherJWTUtil2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC7523Constants;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RFC8628Constants;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.UnknownClientException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.servlet.AbstractServlet;
import edu.uiuc.ncsa.security.servlet.HeaderUtils;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import javax.servlet.http.HttpServletRequest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.ServiceConstantKeys.CONSUMER_KEY;
import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.*;

/**
 * Utilities for dealing with getting tokens that may be either sent as parameters
 * or in the authorization header . Note that you should check that if a user sends both, that they match
 * and throw an exception if they do not.
 * <p>Created by Jeff Gaynor<br>
 * on 9/25/17 at  5:33 PM
 */
public class OA2HeaderUtils extends HeaderUtils {

    public static String getATFromParameter(HttpServletRequest request) {
        String rawID = request.getParameter(OA2Constants.ACCESS_TOKEN);
        if (StringUtils.isTrivial(rawID)) {
            return null;
        }
        return rawID;
    }

    public static Identifier getIDFromParameters(HttpServletRequest request) {
        Identifier paramID = null;

        // assume that the secret and id are in the request
        String rawID = request.getParameter(AbstractServlet.CONST(CONSUMER_KEY));
        if (StringUtils.isTrivial(rawID)) {
            return null;
        }
        return BasicIdentifier.newID(rawID);
    }

    /**
     * Assumption is that the request has the correct {@link RFC7523Constants#CILENT_ASSERTION_TYPE} of
     * {@link RFC7523Constants#ASSERTION_JWT_BEARER}, so we are decoding that.
     *
     * @param request
     */
    public static OA2Client getAndVerifyRFC7523Client(HttpServletRequest request, OA2SE oa2SE) throws NoSuchAlgorithmException, InvalidKeySpecException {
           return getAndVerifyRFC7523Client(request, oa2SE, false); // default is to use token endpoint
    }
    public static OA2Client getAndVerifyRFC7523Client(HttpServletRequest request, OA2SE oa2SE, boolean isDeviceFlow) throws NoSuchAlgorithmException, InvalidKeySpecException {

        String raw = request.getParameter(RFC7523Constants.CILENT_ASSERTION);
        if (StringUtils.isTrivial(raw)) {
            // throw an exception
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "missing " + RFC7523Constants.CILENT_ASSERTION,
                    HttpStatus.SC_BAD_REQUEST, null);

        }
        JSONObject[] hp;
        try {
            hp = MyOtherJWTUtil2.readJWT(raw);
        } catch (IllegalArgumentException iax) {
            // means this is sent as a JWT, but is not one
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, RFC7523Constants.CILENT_ASSERTION + " is not a JWT", HttpStatus.SC_BAD_REQUEST, null);
        } catch (Throwable t) {
            // In this case, it is something like an unsupported algorithm
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "could not decode JWT:" + t.getMessage(), HttpStatus.SC_BAD_REQUEST, null);
        }
        // In order to decode this, we need to get the client ID (required in the sub claim) and grab the key.
        JSONObject json = hp[1];
        String state = json.containsKey(OA2Constants.STATE) ? json.getString(OA2Constants.STATE) : null;
        if (!json.containsKey(SUBJECT)) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "missing " + SUBJECT + " claim, i.e., no client ID", HttpStatus.SC_BAD_REQUEST, state);
        }
        Identifier clientID = BasicIdentifier.newID(json.getString(SUBJECT));
        OA2Client client = (OA2Client) oa2SE.getClientStore().get(clientID);
        if (!oa2SE.getClientApprovalStore().isApproved(clientID)) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT, "client not approved", HttpStatus.SC_BAD_REQUEST, state);
        }
        if (!client.hasJWKS()) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "client does not support RFC 7523", HttpStatus.SC_BAD_REQUEST, state);
        }
// Finally. We can verify the JWT
        try {
            MyOtherJWTUtil2.verifyAndReadJWT(raw, client.getJWKS());
        } catch (Throwable t) {
            // We read the token before without verifying it because we could not. The only error(s) left are if the signature fails.
            throw new OA2GeneralError(OA2Errors.INVALID_TOKEN, "failed to verify token", HttpStatus.SC_BAD_REQUEST, state);
        }

        if (json.containsKey(AUDIENCE)) {
            String serverName = oa2SE.getServiceAddress().toString();
            if(isDeviceFlow){
                serverName = serverName + (serverName.endsWith("/") ? "" : "/") + RFC8628Constants.DEVICE_AUTHORIZATION_ENDPOINT; // construct the device_authorization endpoint
            }else{
                serverName = serverName + (serverName.endsWith("/") ? "" : "/") + "token"; // construct the token endpoint
            }
            if (!json.getString(AUDIENCE).equals(serverName)) {
                throw new IllegalArgumentException("wrong " + AUDIENCE);
            }
        } else {
            throw new IllegalArgumentException("missing " + AUDIENCE);
        }
        // Not clear what the issuer should be, aside from the OIDC spec., so we accept that as
        // reasonable and assume it is just the client
        if (json.containsKey(ISSUER)) {
            Identifier id = BasicIdentifier.newID(json.getString(ISSUER));
            if (!client.getIdentifier().equals(id)) {
                throw new UnknownClientException("unknown " + ISSUER + " with id \"" + id + "\"");
            }

        } else {
            throw new IllegalArgumentException("missing " + ISSUER);
        }
        if (json.containsKey(EXPIRATION)) {
            if (json.getLong(EXPIRATION) * 1000 < System.currentTimeMillis()) {
                throw new IllegalArgumentException("Expired token ");
            }
        } else {
            throw new IllegalArgumentException("missing " + EXPIRATION);
        }
        // issued at does not concern us at this time. Might limit it by
        // policy in the future.
        if (json.containsKey(NOT_VALID_BEFORE)) {
            if (System.currentTimeMillis() < json.getLong(NOT_VALID_BEFORE) * 1000) {
                throw new IllegalArgumentException("Token is not valid yet");
            }
        }
        return client;
    }

    public static OA2Client getRFC7523Client(HttpServletRequest request, OA2SE oa2SE) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String raw = request.getParameter(RFC7523Constants.CILENT_ASSERTION);
        if (StringUtils.isTrivial(raw)) {
            // throw an exception
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "missing " + RFC7523Constants.CILENT_ASSERTION,
                    HttpStatus.SC_BAD_REQUEST, null);

        }
        JSONObject[] hp;
        try {
            hp = MyOtherJWTUtil2.readJWT(raw);
        } catch (IllegalArgumentException iax) {
            // means this is sent as a JWT, but is not one
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, RFC7523Constants.CILENT_ASSERTION + " is not a JWT", HttpStatus.SC_BAD_REQUEST, null);
        } catch (Throwable t) {
            // In this case, it is something like an unsupported algorithm
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "could not decode JWT:" + t.getMessage(), HttpStatus.SC_BAD_REQUEST, null);
        }
        // In order to decode this, we need to get the client ID (required in the sub claim) and grab the key.
        JSONObject json = hp[1];
        String state = json.containsKey(OA2Constants.STATE) ? json.getString(OA2Constants.STATE) : null;
        if (!json.containsKey(SUBJECT)) {
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "missing " + SUBJECT + " claim, i.e., no client ID", HttpStatus.SC_BAD_REQUEST, state);
        }
        Identifier clientID = BasicIdentifier.newID(json.getString(SUBJECT));
        OA2Client client = (OA2Client) oa2SE.getClientStore().get(clientID);
        if (!oa2SE.getClientApprovalStore().isApproved(clientID)) {
            throw new OA2GeneralError(OA2Errors.UNAUTHORIZED_CLIENT, "client not approved", HttpStatus.SC_BAD_REQUEST, state);
        }
        return client;
    }

    public static void verifyRFC7523Client(OA2Client client, HttpServletRequest request, OA2SE oa2SE) throws NoSuchAlgorithmException, InvalidKeySpecException {
        String raw = request.getParameter(RFC7523Constants.CILENT_ASSERTION);
        if (StringUtils.isTrivial(raw)) {
                // throw an exception
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                        "missing " + RFC7523Constants.CILENT_ASSERTION,
                        HttpStatus.SC_BAD_REQUEST, null);

            }
            JSONObject[] hp;
            try {
                hp = MyOtherJWTUtil2.readJWT(raw);
            } catch (IllegalArgumentException iax) {
                // means this is sent as a JWT, but is not one
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, RFC7523Constants.CILENT_ASSERTION + " is not a JWT", HttpStatus.SC_BAD_REQUEST, null);
            } catch (Throwable t) {
                // In this case, it is something like an unsupported algorithm
                throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "could not decode JWT:" + t.getMessage(), HttpStatus.SC_BAD_REQUEST, null);
            }
            JSONObject json = hp[1];
        String state = json.containsKey(OA2Constants.STATE) ? json.getString(OA2Constants.STATE) : null;

          if (!client.hasJWKS()) {
              throw new OA2GeneralError(OA2Errors.INVALID_REQUEST, "client does not support RFC 7523", HttpStatus.SC_BAD_REQUEST, state);
          }
  // Finally. We can verify the JWT
          try {
              MyOtherJWTUtil2.verifyAndReadJWT(raw, client.getJWKS());
          } catch (Throwable t) {
              // We read the token before without verifying it because we could not. The only error(s) left are if the signature fails.
              throw new OA2GeneralError(OA2Errors.INVALID_TOKEN, "failed to verify token", HttpStatus.SC_BAD_REQUEST, state);
          }

          if (json.containsKey(AUDIENCE)) {
              String serverName = oa2SE.getServiceAddress().toString();
              serverName = serverName + (serverName.endsWith("/") ? "" : "/") + "token"; // construct the token endpoint
              if (!json.getString(AUDIENCE).equals(serverName)) {
                  throw new IllegalArgumentException("wrong " + AUDIENCE);
              }
          } else {
              throw new IllegalArgumentException("missing " + AUDIENCE);
          }
          // Not clear what the issuer should be, aside from the OIDC spec., so we accept that as
          // reasonable and assume it is just the client
          if (json.containsKey(ISSUER)) {
              Identifier id = BasicIdentifier.newID(json.getString(ISSUER));
              if (!client.getIdentifier().equals(id)) {
                  throw new UnknownClientException("unknown " + ISSUER + " with id \"" + id + "\"");
              }

          } else {
              throw new IllegalArgumentException("missing " + ISSUER);
          }
          if (json.containsKey(EXPIRATION)) {
              if (json.getLong(EXPIRATION) * 1000 < System.currentTimeMillis()) {
                  throw new IllegalArgumentException("Expired token ");
              }
          } else {
              throw new IllegalArgumentException("missing " + EXPIRATION);
          }
          // issued at does not concern us at this time. Might limit it by
          // policy in the future.
          if (json.containsKey(NOT_VALID_BEFORE)) {
              if (System.currentTimeMillis() < json.getLong(NOT_VALID_BEFORE) * 1000) {
                  throw new IllegalArgumentException("Token is not valid yet");
              }
          }
    }


}