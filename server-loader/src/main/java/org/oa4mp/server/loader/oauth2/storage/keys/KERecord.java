package org.oa4mp.server.loader.oauth2.storage.keys;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.storage.monitored.Monitored;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeyUtil;
import edu.uiuc.ncsa.security.util.jwk.JWKUtil2;
import net.sf.json.JSONObject;

import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Date;

/**
 * Store entry that modesl a single JWK key. It contains all the administrative
 * information for the key, as well as the actual key itself.
 * <p>
 * Each key has a VI (no VI means default). Much of this is aslo in the key itself, but
 * this allows for searching and better management.
 */
public class KERecord extends Monitored {
    public KERecord(Identifier identifier) {
        super(identifier);
    }

    protected String alg = "alg";
    protected Boolean isValid = false;
    protected Date exp = null;
    protected Date iat = null;
    protected Boolean isDefault = false;
    protected JSONWebKey jwk = null;
    protected String kid = "kid";
    protected String kty = "kty";
    protected Date nbf = null;
    protected String use = "use";
    protected URI vi = null;

    public String getAlg() {
        return alg;
    }

    public void setAlg(String alg) {
        this.alg = alg;
    }

    public Boolean getValid() {
        return isValid;
    }

    public void setValid(Boolean valid) {
        isValid = valid;
    }

    public Date getExp() {
        return exp;
    }

    public void setExp(Date exp) {
        this.exp = exp;
    }

    public Date getIat() {
        return iat;
    }

    public void setIat(Date iat) {
        this.iat = iat;
    }

    public Boolean getDefault() {
        return isDefault;
    }

    public void setDefault(Boolean aDefault) {
        isDefault = aDefault;
    }

    /**
     * Gets the stored version of this key with little or no acocunting information.
     * Use the {@link #toJWK()} to convert this record to a usuable JWK.
     *
     * @return
     */
    public JSONWebKey getJwk() {
        return jwk;
    }

    public void setJwk(JSONWebKey jwk) {
        this.jwk = jwk;
    }

    public String getKid() {
        return kid;
    }

    public void setKid(String kid) {
        this.kid = kid;
    }

    public String getKty() {
        return kty;
    }

    public void setKty(String kty) {
        this.kty = kty;
    }

    public Date getNbf() {
        return nbf;
    }

    public void setNbf(Date nbf) {
        this.nbf = nbf;
    }

    public String getUse() {
        return use;
    }

    public void setUse(String use) {
        this.use = use;
    }

    public URI getVi() {
        return vi;
    }

    public void setVi(URI vi) {
        this.vi = vi;
    }

    /**
     * If there is a virtual issuer set. No VI means this is in the default issuer.
     *
     * @return
     */
    public boolean hasVI() {
        return vi != null;
    }

    /**
     * Imports the {@link JSONWebKey} into this record. At the end, the recrod
     * represents the web key. See also {@link #toJWK()}.
     * <h3>Note</h3>
     * The key is not set valid automatically, since that is not part of the actual
     * key, nor is there a description or virtual issuer set.
     *
     * @param jwk
     * @param isDefault
     */
    public void fromJWK(JSONWebKey jwk, boolean isDefault) throws NoSuchAlgorithmException, InvalidKeySpecException {
        setDefault(isDefault);
        setUse(jwk.use);
        setKty(jwk.type);
        setAlg(jwk.algorithm);
        setKid(jwk.id);
        setExp(jwk.expiresAt);
        setIat(jwk.issuedAt);
        setNbf(jwk.notValidBefore);
        Date now = new Date();
        setCreationTS(now);
        setLastAccessed(now);
        setLastModifiedTS(now);
        setValid(false);
        JSONObject json = JSONWebKeyUtil.toJSON(jwk);
        json.remove(JWKUtil2.EXPIRES_AT);
        json.remove(JWKUtil2.ISSUED_AT);
        json.remove(JWKUtil2.NOT_VALID_BEFORE);
        setJwk(JSONWebKeyUtil.fromJSON(json).get(getKid()));
        setLastModifiedTS(new Date());
        setCreationTS(new Date());
        setLastModifiedTS(new Date());
    }

    /**
     * Takes this record and returns the {@link JSONWebKey} with all fields set.
     * You should use this if you need to export the key for use and {@link #getJwk()}
     * if you need the raw, unprocessed key.
     *
     * @return
     */
    public JSONWebKey toJWK() throws NoSuchAlgorithmException, InvalidKeySpecException {
        // We don't want to just hand over the jwk in this objectg since
        // the user might change the state of the stored object. Clone it
        // and let them have their own copy.
        JSONObject json = JSONWebKeyUtil.toJSON(getJwk());
        JSONWebKey jwk2 = JSONWebKeyUtil.fromJSON(json).get(getKid());
        jwk2.expiresAt = getExp();
        jwk2.issuedAt = getIat();
        jwk2.notValidBefore = getNbf();
        return jwk2;
    }
}
