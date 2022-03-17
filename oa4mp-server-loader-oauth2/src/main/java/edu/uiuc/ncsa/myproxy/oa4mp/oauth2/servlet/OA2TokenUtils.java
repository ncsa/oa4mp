package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2SE;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.RefreshTokenStore;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.tx.TXRecord;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo.VirtualOrganization;
import edu.uiuc.ncsa.security.core.exceptions.InvalidAlgorithmException;
import edu.uiuc.ncsa.security.core.exceptions.InvalidSignatureException;
import edu.uiuc.ncsa.security.core.exceptions.UnsupportedJWTTypeException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.TokenUtils;
import edu.uiuc.ncsa.security.oauth_2_0.*;
import edu.uiuc.ncsa.security.servlet.ServletDebugUtil;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONException;
import net.sf.json.JSONObject;
import org.apache.http.HttpStatus;

import java.io.IOException;
import java.net.URI;

import static edu.uiuc.ncsa.myproxy.oa4mp.server.servlet.MyProxyDelegationServlet.getServiceEnvironment;
import static edu.uiuc.ncsa.security.oauth_2_0.server.claims.OA2Claims.JWT_ID;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 5/19/21 at  8:37 AM
 */
public class OA2TokenUtils {
    /**
     * Get the right set of keys, either from the service environment or the correct virtual organization.
     * @param oa2se
     * @param client
     * @return
     */
    public static JSONWebKeys getKeys(OA2SE oa2se, OA2Client client) {
        VirtualOrganization vo = oa2se.getVO(client.getIdentifier());
        //CIL-974
        JSONWebKeys keys = ((OA2SE) getServiceEnvironment()).getJsonWebKeys();

        if (vo != null) {
            keys = vo.getJsonWebKeys();
            ServletDebugUtil.trace(OA2TokenUtils.class, "Got VO for client " + client.getIdentifierString());
        }
        return keys;
    }

    /**
     * Takes the subjectToken from the raw input (performing a base 32 decoding if needed)
     * and returns the access token.
     * @param subjectToken
     * @param oa2se
     * @param keys
     * @return
     */
    public static AccessTokenImpl getAT(String subjectToken, OA2SE oa2se, JSONWebKeys keys) {
        if (TokenUtils.isBase32(subjectToken)) {
              subjectToken = TokenUtils.b32DecodeToken(subjectToken);
          }
        AccessTokenImpl accessToken;
        JSONObject sciTokens;
        OA2TokenForge tokenForge = (OA2TokenForge) oa2se.getTokenForge();
        try {
            sciTokens = JWTUtil.verifyAndReadJWT(subjectToken, keys);
            //accessToken = tokenForge.getAccessToken(sciTokens.getString(JWT_ID));
            accessToken = new AccessTokenImpl(subjectToken, URI.create(sciTokens.getString(JWT_ID)));
        } catch (JSONException | IllegalArgumentException tt) {
            // didn't work, so now we assume it is regular token
            ServletDebugUtil.trace(OA2TokenUtils.class, "failed to parse access token as JWT:" + tt.getMessage());
            accessToken = (AccessTokenImpl) oa2se.getTokenForge().getAccessToken(subjectToken);
        } catch (InvalidSignatureException | InvalidAlgorithmException | UnsupportedJWTTypeException tt) {
            ServletDebugUtil.trace(OA2TokenUtils.class, "Failed to verify access token JWT: \"" + tt.getMessage());
            throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                    "invalid access token",
                    HttpStatus.SC_BAD_REQUEST,
                    null);
        }
        ServletDebugUtil.trace(OA2TokenUtils.class, "access token from subject token = " + accessToken);


        OA2ServiceTransaction t = (OA2ServiceTransaction) oa2se.getTransactionStore().get(accessToken);

        if (t != null) {
            // Must present a valid token to get one.
            if (!t.isAccessTokenValid()) {
                throw new OA2ATException(OA2Errors.INVALID_TOKEN,
                        "token invalid",
                        t.getRequestState());
            }
            if (accessToken.isExpired()) {
                throw new OA2ATException(OA2Errors.INVALID_TOKEN,
                        "token expired",
                        t.getRequestState());
            }
        }
        return accessToken;
    }

    /**
     * Takes the subjectToken from the raw input (performing a base 32 decoding if needed)
     * and returns the refresh token.
     * @param subjectToken
     * @param oa2SE
     * @param keys
     * @return
     */
    public static RefreshTokenImpl getRT(String subjectToken, OA2SE oa2SE, JSONWebKeys keys){
        if (TokenUtils.isBase32(subjectToken)) {
              subjectToken = TokenUtils.b32DecodeToken(subjectToken);
          }
        RefreshTokenImpl refreshToken;
        OA2TokenForge tokenForge = (OA2TokenForge) oa2SE.getTokenForge();
        try {
               JSONObject tt = JWTUtil.verifyAndReadJWT(subjectToken, keys);
               refreshToken = new RefreshTokenImpl(subjectToken, URI.create(tt.getString(JWT_ID)));
           } catch (JSONException | IllegalArgumentException tt) {
               ServletDebugUtil.trace(OA2TokenUtils.class, "Failed to parse refresh token as JWT:" + tt.getMessage());
               refreshToken = tokenForge.getRefreshToken(subjectToken);
           } catch (InvalidSignatureException | InvalidAlgorithmException | UnsupportedJWTTypeException tt) {
               ServletDebugUtil.trace(OA2TokenUtils.class, "Failed to verify refresh token JWT: \"" + tt.getMessage());
               throw new OA2GeneralError(OA2Errors.INVALID_REQUEST,
                       "invalid refresh token",
                       HttpStatus.SC_BAD_REQUEST,
                       null);
           }
           ServletDebugUtil.trace(OA2TokenUtils.class, "refresh token from subject token = " + refreshToken);
        OA2ServiceTransaction t;
           try {
               RefreshTokenStore zzz = (RefreshTokenStore) oa2SE.getTransactionStore(); // better to get a class cast exception here
                t = zzz.get(refreshToken);
           } catch (Throwable tt) {
               ServletDebugUtil.error(OA2TokenUtils.class, "error getting refresh token:" + refreshToken + " message:" + tt.getMessage());
               throw new OA2ATException(OA2Errors.INVALID_GRANT, "invalid refresh token");
           }
           if (t != null) {
               // Must present a valid token to get one.
               if (!t.isRefreshTokenValid()) {
                   throw new OA2ATException(OA2Errors.INVALID_GRANT,
                           "invalid refresh token",
                           t.getRequestState());
               }
               if (refreshToken.isExpired()) {
                   throw new OA2ATException(OA2Errors.INVALID_GRANT,
                           "expired refresh token",
                           t.getRequestState());
               }
           }
           return refreshToken;
    }

    /**
     * Given an access token (and transaction if available), Find the actual transaction. This may involve a look up
     * in the tx store
     * @param accessToken
     * @param oa2se
     * @return
     * @throws IOException
     */
    public static OA2ServiceTransaction getTransactionFromTX(OA2SE oa2se, AccessTokenImpl accessToken) throws IOException {
        return getTransactionFromTX(oa2se, accessToken.getJti());
      }

    public static OA2ServiceTransaction getTransactionFromTX(OA2SE oa2se, RefreshTokenImpl refreshToken) throws IOException {
        return getTransactionFromTX(oa2se, refreshToken.getJti());
      }

    protected static OA2ServiceTransaction getTransactionFromTX(OA2SE oa2se, URI jti) throws IOException {
          TXRecord txRecord= (TXRecord) oa2se.getTxStore().get(BasicIdentifier.newID(jti));
          if (txRecord == null) {
              ServletDebugUtil.trace(OA2TokenUtils.class, "No transaction found, no TXRecord found for token with id = " + jti);
              throw new OA2GeneralError(OA2Errors.INVALID_TOKEN,
                      "token not found",
                      HttpStatus.SC_UNAUTHORIZED,
                      null);
          }
          if (!txRecord.isValid()) {
              throw new OA2ATException(OA2Errors.INVALID_TOKEN,
                      "invalid token",
                      null);
          }
          if (txRecord.getExpiresAt() < System.currentTimeMillis()) {
              throw new OA2ATException(OA2Errors.INVALID_TOKEN,
                      "token expired",
                      null);
          }
          return (OA2ServiceTransaction) oa2se.getTransactionStore().get(txRecord.getParentID());
      }

}
