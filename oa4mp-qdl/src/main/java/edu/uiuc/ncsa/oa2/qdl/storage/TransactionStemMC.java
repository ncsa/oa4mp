package edu.uiuc.ncsa.oa2.qdl.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.OA2ServiceTransaction;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.OA2TransactionKeys;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.qdl.exceptions.QDLException;
import edu.uiuc.ncsa.qdl.variables.StemVariable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.delegation.server.storage.ClientStore;
import edu.uiuc.ncsa.security.delegation.token.MyX509Certificates;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.security.delegation.token.impl.VerifierImpl;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import edu.uiuc.ncsa.security.util.pkcs.CertUtil;
import net.sf.json.JSONObject;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import static edu.uiuc.ncsa.security.core.util.StringUtils.isTrivial;
import static edu.uiuc.ncsa.security.util.pkcs.CertUtil.fromPEM;

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

    @Override
    public V fromMap(StemVariable stem, V v) {
        v = super.fromMap(stem, v);
        Identifier id = v.getIdentifier();
        if (stem.containsKey(kk().authGrant())) {
            v.setAuthorizationGrant(new AuthorizationGrantImpl(URI.create(stem.getString(kk().authGrant()))));
        }
        if (stem.containsKey(kk().authzGrantLifetime())) {
            v.setAuthGrantLifetime(stem.getLong(kk().authzGrantLifetime()));
        }
        if (stem.containsKey(kk().tempCredValid())) {
            v.setAuthGrantValid(stem.getBoolean(kk().tempCredValid()));
        }

        if (stem.containsKey(kk().accessToken())) {
            v.setAccessToken(new AccessTokenImpl(URI.create(stem.getString(kk().accessToken()))));
        }
        if (stem.containsKey(kk().accessTokenValid())) {
            v.setAccessTokenValid(stem.getBoolean(kk().accessTokenValid()));
        }
        if (stem.containsKey(kk().expiresIn())) {
            v.setAccessTokenLifetime(stem.getLong(kk().expiresIn()));
        }

        if (stem.containsKey(kk().refreshToken())) {
            v.setRefreshToken(new RefreshTokenImpl(URI.create(stem.getString(kk().refreshToken()))));
        }
        if (stem.containsKey(kk().refreshTokenLifetime())) {
            v.setRefreshTokenLifetime(stem.getLong(kk().refreshTokenLifetime()));
        }
        if (stem.containsKey(kk().refreshTokenValid())) {
            v.setRefreshTokenValid(stem.getBoolean(kk().refreshTokenValid()));
        }

        if (stem.containsKey(kk().verifier())) {
            v.setVerifier(new VerifierImpl(URI.create(stem.getString(kk().verifier()))));
        }
        if (stem.containsKey(kk().lifetime())) {
            v.setLifetime(stem.getLong(kk().lifetime()));
        }
        if (isStringKeyOK(stem, kk().certReq())) {
            v.setCertReq(CertUtil.fromStringToCertReq(stem.getString(kk().certReq())));
        }
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
        if(stem.containsKey(kk().clientKey())){
            v.setClient((OA2Client) clientStore.get(BasicIdentifier.newID(stem.getString(kk().clientKey()))));
        }
        if(isStringKeyOK(stem,kk().username())){
               v.setUsername(stem.getString(kk().username()));
        }
        if(isStringKeyOK(stem, kk().myproxyUsername())){
            v.setMyproxyUsername(stem.getString(kk().myproxyUsername()));
        }
        if(isStringKeyOK(stem, kk().nonce())){
            v.setNonce(stem.getString(kk().nonce()));
        }
        if(isStringKeyOK(stem, kk().states())){
            v.setState(JSONObject.fromObject(stem.getString(kk().states())));
        }

        /*

         */
        v.setIdentifier(id); // Be SURE it is right.
        return v;
    }

    /*
       protected String authzGrantLifetime = "authz_grant_lifetime";
  protected String refreshToken = "refresh_token";
  protected String refreshTokenLifetime = "refresh_token_lifetime";
  protected String refreshTokenValid = "refresh_token_valid";
  protected String expiresIn = "expires_in";
  protected String scopes = "scopes";
  protected String authTime = "auth_time";
  protected String states = "states";
     */
    @Override
    public StemVariable toMap(V v, StemVariable stem) {
        stem = super.toMap(v, stem);
        if (v.hasAuthorizationGrant()) {
            stem.put(kk().authGrant(), v.getAuthorizationGrant().getToken());
        }
        if (v.hasVerifier()) {
            stem.put(kk().verifier(), v.getVerifier().getToken());
        }
        stem.put(kk().tempCredValid(), v.isAuthGrantValid());
        stem.put(kk().lifetime(), v.getLifetime());

        if (v.getCertReq() != null) {
            stem.put(kk().certReq(), CertUtil.fromCertReqToString(v.getCertReq()));
        }
        MyX509Certificates myCert = (MyX509Certificates) v.getProtectedAsset();
        if (!(myCert == null || myCert.getX509Certificates() == null || myCert.getX509Certificates().length == 0)) {
            try {
                stem.put(kk().cert(), myCert.getX509CertificatesPEM());
            } catch (CertificateEncodingException e) {
                throw new QDLException("Error: could not encode certificate", e);
            }

        }
        if (v.getClient() != null) {
            stem.put(kk().clientKey(), v.getClient().getIdentifierString());
        }
        if (!isTrivial(v.getUsername())) {
            stem.put(kk().username(), v.getUsername());
        }
        if (!isTrivial(v.getMyproxyUsername())) {
            stem.put(kk().myproxyUsername(), v.getMyproxyUsername());
        }

        if (v.getRefreshToken() != null) {
            stem.put(kk().refreshToken(), v.getRefreshToken().getToken());
        }
        stem.put(kk().refreshTokenValid(), v.isRefreshTokenValid());
        stem.put(kk().refreshTokenLifetime(), v.getRefreshTokenLifetime());

        if (v.getAccessToken() != null) {
            stem.put(kk().accessToken(), v.getAccessToken().getToken());
        }
        stem.put(kk().accessTokenValid(), v.isAccessTokenValid());
        stem.put(kk().expiresIn(), v.getAccessTokenLifetime());
        if (v.getCallback() != null) {
            stem.put(kk().callbackUri(), v.getCallback().toString());
        }
        if (!isTrivial(v.getNonce())) {
            stem.put(kk().nonce(), v.getNonce());
        }
        fromList(v.getScopes(), stem, kk().scopes());
        if (v.hasAuthTime()) {
            stem.put(kk().authTime(), v.getAuthTime().getTime());
        }
        if (v.getState() != null) {
            stem.put(kk().states(), v.getState().toString());
        }
        return stem;
    }
}
