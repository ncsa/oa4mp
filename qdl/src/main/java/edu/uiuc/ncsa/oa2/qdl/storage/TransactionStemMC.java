package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.transactions.OA2TransactionKeys;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.MyX509Certificates;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.*;
import edu.uiuc.ncsa.oa4mp.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.qdl.variables.QDLStem;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import net.sf.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.Date;

import static edu.uiuc.ncsa.security.util.pkcs.MyCertUtil.fromPEM;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/21/20 at  7:17 AM
 */
public class TransactionStemMC<V extends OA2ServiceTransaction> extends StemConverter<V> {
    public TransactionStemMC(MapConverter<V> mapConverter, ClientStore clientStore) {
        super(mapConverter);
        this.clientStore = clientStore;
    }

    ClientStore clientStore;

    protected OA2TransactionKeys kk() {
        return (OA2TransactionKeys) keys;
    }

    /*
    Basic transaction keys (4)
    String accessToken = "access_token";
    String authGrant = "auth_grant"; // Changes require that temp_token be used solely as the id.
    String verifier = "oauth_verifier";
    String tempCred = "temp_token";

    Service transaction Keys  (5)
    String accessTokenValid = "access_token_valid";
    protected String lifetime = "certlifetime";
    String nonce = "nonce";
    String callbackUri = "oauth_callback";
    String tempCredValid = "temp_token_valid";

    DTransaction keys (5)
    String certReq = "certreq";
    String cert = "certificate";
    String clientKey = "oauth_consumer_key";
    String username = "username";
    String myproxyUsername = "myproxyUsername";

    OA2 specific keys (14)
    protected String authTime = "auth_time";
    protected String atJWT = "at_jwt";
    protected String authzGrantLifetime = "authz_grant_lifetime";
    protected String expiresIn = "expires_in";
    protected String isRFC8628  = "is_rfc_8628";
    protected String proxyID  = "proxy_id";
    protected String refreshToken = "refresh_token";
    protected String rtJWT = "rt_jwt";

    protected String refreshTokenLifetime = "refresh_token_lifetime";
    protected String refreshTokenValid = "refresh_token_valid";
    protected String reqState = "req_state";
    protected String scopes = "scopes";
    protected String states = "states";

    protected String userCode  = "user_code";
    protected String validatedScopes  = "validated_scopes";

     */

    @Override
    public V fromMap(QDLStem stem, V v) {
        v = super.fromMap(stem, v);
        Identifier id = v.getIdentifier();
        /*
          Each block of attributes is by subclass.
         */
        // =====
        /*
         String accessToken = "access_token";
        String authGrant = "auth_grant"; // Changes require that temp_token be used solely as the id.
        String verifier = "oauth_verifier";
        String tempCred = "temp_token";  // This is not used in OA2, but because of class inheritence from OA 1 is in the list
         */
        //if (stem.containsKey(kk().accessToken())) {v.setAccessToken(new AccessTokenImpl(URI.create(stem.getString(kk().accessToken()))));}
        if (stem.containsKey(kk().accessToken())) {v.setAccessToken(TokenFactory.createAT(stem.getString(kk().accessToken())));}
        //if (stem.containsKey(kk().authGrant())) {v.setAuthorizationGrant(new AuthorizationGrantImpl(URI.create(stem.getString(kk().authGrant()))));}
        if (stem.containsKey(kk().authGrant())) {v.setAuthorizationGrant(TokenFactory.createAG(stem.getString(kk().authGrant())));}
        if(stem.containsKey(kk().verifier())){v.setVerifier(new VerifierImpl(URI.create(stem.getString(kk().verifier()))));}
        // 3 (4th unused)
        // ======
        /*
        String accessTokenValid = "access_token_valid";
        String lifetime = "certlifetime";
        String callbackUri = "oauth_callback";
        String nonce = "nonce";
        String tempCredValid = "temp_token_valid";
         */
        if (stem.containsKey(kk().accessTokenValid())) {v.setAccessTokenValid(stem.getBoolean(kk().accessTokenValid()));}
        if (stem.containsKey(kk().lifetime())) {v.setLifetime(stem.getLong(kk().lifetime()));}
        if (stem.containsKey(kk().idTokenLifetime())) {v.setIDTokenLifetime(stem.getLong(kk().idTokenLifetime()));}
        if(stem.containsKey(kk().callbackUri())){v.setCallback(URI.create(stem.getString(kk().callbackUri())));}
        if(isStringKeyOK(stem, kk().nonce())){v.setNonce(stem.getString(kk().nonce()));}
        if (stem.containsKey(kk().tempCredValid())) {v.setAuthGrantValid(stem.getBoolean(kk().tempCredValid()));}
        // 5 attributes
      // ===
        /*
                 String certReq = "certreq";
                String cert = "certificate";
                String clientKey = "oauth_consumer_key";
                String username = "username";
                String myproxyUsername = "myproxyUsername";

         */

        if (isStringKeyOK(stem, kk().certReq())) {v.setCertReq(CertUtil.fromStringToCertReq(stem.getString(kk().certReq())));}
        if (isStringKeyOK(stem, kk().cert())) {
            try {
                ByteArrayInputStream baos = new ByteArrayInputStream(stem.getString(kk().cert()).getBytes("UTF-8"));
                MyX509Certificates myCert = new MyX509Certificates(fromPEM(baos));
                v.setProtectedAsset(myCert);
            } catch (CertificateException e) {
                throw new GeneralException("Error decoding certificate", e);
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
        }
        if(stem.containsKey(kk().clientKey())){v.setClient((OA2Client) clientStore.get(BasicIdentifier.newID(stem.getString(kk().clientKey()))));}
        if(isStringKeyOK(stem,kk().username())){v.setUsername(stem.getString(kk().username()));}
        if(isStringKeyOK(stem, kk().myproxyUsername())){v.setMyproxyUsername(stem.getString(kk().myproxyUsername()));}
        // 5 attributes

      // ===
        /*
        protected String authTime = "auth_time";
        protected String authzGrantLifetime = "authz_grant_lifetime";
        protected String expiresIn = "expires_in";
        protected String idTokenIdentifier  = "id_token_identifier";
        protected String isRFC8628  = "is_rfc_8628";
        protected String refreshToken = "refresh_token";
        protected String refreshTokenLifetime = "refresh_token_lifetime";
        protected String refreshTokenValid = "refresh_token_valid";
        protected String reqState = "req_state";
        protected String scopes = "scopes";
        protected String states = "states";
        protected String userCode  = "user_code";
        protected String validatedScopes  = "validated_scopes";

         */
        if (stem.containsKey(kk().authTime())) {
            Date date = new Date(stem.getLong(kk().authTime()));
            v.setAuthTime(date);
        }
        if (stem.containsKey(kk().atJWT())) {v.setATJWT(stem.getString(kk().atJWT()));}
        if (stem.containsKey(kk().authzGrantLifetime())) {v.setAuthGrantLifetime(stem.getLong(kk().authzGrantLifetime()));}
        if (stem.containsKey(kk().expiresIn())) {v.setAccessTokenLifetime(stem.getLong(kk().expiresIn()));}
        if(stem.containsKey(kk().idTokenIdentifier())){v.setIDTokenIdentifier(stem.getString(kk().idTokenIdentifier()));        }
        if(stem.containsKey(kk().isRFC8628())){v.setRFC8628Request(stem.getBoolean(kk().isRFC8628()));        }
        if(stem.containsKey(kk().proxyID())){v.setProxyId(stem.getString(kk().proxyID()));        }
        //if (stem.containsKey(kk().refreshToken())) {v.setRefreshToken(new RefreshTokenImpl(URI.create(stem.getString(kk().refreshToken()))));}
        if (stem.containsKey(kk().refreshToken())) {v.setRefreshToken(TokenFactory.createRT(stem.getString(kk().refreshToken())));}
        if (stem.containsKey(kk().rtJWT())) {v.setRTJWT(stem.getString(kk().rtJWT()));}
        // 5
        if (stem.containsKey(kk().refreshTokenLifetime())) {v.setRefreshTokenLifetime(stem.getLong(kk().refreshTokenLifetime()));}
        if (stem.containsKey(kk().refreshTokenExpiresAt())) {v.setRefreshTokenExpiresAt(stem.getLong(kk().refreshTokenExpiresAt()));}
        if (stem.containsKey(kk().refreshTokenValid())) {v.setRefreshTokenValid(stem.getBoolean(kk().refreshTokenValid()));}
        if(stem.containsKey(kk().reqState())){v.setRequestState(stem.getString(kk().reqState()));}
        if(stem.containsKey(kk().scopes())){v.setScopes(toList(stem,kk().scopes()));}
        if(isStringKeyOK(stem, kk().states())){v.setState(JSONObject.fromObject(stem.getString(kk().states())));}
        // 10
        if(stem.containsKey(kk().userCode())){v.setUserCode(stem.getString(kk().userCode()));}
        if(stem.containsKey(kk().validatedScopes())){v.setValidatedScopes(toList(stem,kk().validatedScopes()));}
        // 12 attributes
        v.setIdentifier(id); // Be SURE it is right since it possible that it gets munged some place!
        return v;
    }


    @Override
    public QDLStem toMap(V v, QDLStem stem) {
        stem = super.toMap(v, stem);
        if(v.getAccessToken() != null){stem.put(kk().accessToken(), v.getAccessToken().getToken());}
        if(v.getAuthorizationGrant()!=null) {stem.put(kk().authGrant(), v.getAuthorizationGrant().getToken());}
        if(v.getVerifier()!=null) {stem.put(kk().verifier(), v.getVerifier().getToken());}
        // 3 attribute
        stem.put(kk().accessTokenValid(), v.isAccessTokenValid());
        stem.put(kk().lifetime(), v.getLifetime());
        if(v.getCallback()!=null) {setNonNullStemValue(stem, kk().callbackUri(), v.getCallback().toString());}
        setNonNullStemValue(stem,kk().nonce(), v.getNonce());
        stem.put(kk().tempCredValid(), v.isAuthGrantValid());
        // 5 attributes
        if (v.getCertReq() != null) {stem.put(kk().certReq(), CertUtil.fromCertReqToString(v.getCertReq()));}
        MyX509Certificates myCert = (MyX509Certificates) v.getProtectedAsset();
        if (!(myCert == null || myCert.getX509Certificates() == null || myCert.getX509Certificates().length == 0)) {
            try {
                stem.put(kk().cert(), myCert.getX509CertificatesPEM());
            } catch (CertificateEncodingException e) {
                throw new IllegalArgumentException("could not encode certificate", e);
            }

        }
        if(v.getClient()!=null) {setNonNullStemValue(stem, kk().clientKey(), v.getClient().getIdentifierString());}
        setNonNullStemValue(stem,kk().username(), v.getUsername());
        setNonNullStemValue(stem,kk().myproxyUsername(), v.getMyproxyUsername());
        // 5 attributes
        /*
    protected String authTime = "auth_time";
    protected String atJWT = "at_jwt";
    protected String authzGrantLifetime = "authz_grant_lifetime";
    protected String expiresIn = "expires_in";
    protected String isRFC8628  = "is_rfc_8628";
    protected String proxyID  = "proxy_id";
    protected String refreshToken = "refresh_token";
    protected String refreshTokenLifetime = "refresh_token_lifetime";
    protected String refreshTokenValid = "refresh_token_valid";
    protected String reqState = "req_state";
    protected String rtJWT = "rt_jwt";
    protected String scopes = "scopes";
    protected String states = "states";
    protected String userCode  = "user_code";
    protected String validatedScopes  = "validated_scopes";

         */
        if(v.getAuthTime() != null) {
            stem.put(kk().authTime(), v.getAuthTime().getTime());
        }
        stem.put(kk().authzGrantLifetime(), v.getAuthzGrantLifetime());
        // NOTE this is very old. expires in now refers to access token lifetime
        stem.put(kk().expiresIn(), v.getAccessTokenLifetime());
        stem.put(kk().isRFC8628(), v.isRFC8628Request());

        setNonNullStemValue(stem, kk().idTokenIdentifier(), v.getIDTokenIdentifier());
        setNonNullStemValue(stem, kk().proxyID(), v.getProxyId());
        setNonNullStemValue(stem, kk().atJWT(), v.getATJWT());
        setNonNullStemValue(stem, kk().rtJWT(), v.getRTJWT());
        if (v.getRefreshToken() != null) {
            stem.put(kk().refreshToken(), v.getRefreshToken().getToken());
        }
        // 5 attributes
        stem.put(kk().idTokenLifetime(), v.getIDTokenLifetime());
        stem.put(kk().refreshTokenLifetime(), v.getRefreshTokenLifetime());
        stem.put(kk().refreshTokenExpiresAt(), v.getRefreshTokenExpiresAt());
        stem.put(kk().refreshTokenValid(), v.isRefreshTokenValid());
        setNonNullStemValue(stem, kk().reqState(), v.getRequestState());
        fromList(v.getScopes(), stem, kk().scopes());
        if (v.getState() != null) {
            stem.put(kk().states(), v.getState().toString());
        }
        // 10 attributes
        setNonNullStemValue(stem, kk().userCode(), v.getUserCode());
        if(v.getValidatedScopes()!=null && !v.getValidatedScopes().isEmpty()){fromList(v.getValidatedScopes(), stem, kk().validatedScopes());}
        // 12 attributes
        return stem;
    }
}
