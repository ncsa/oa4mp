package edu.uiuc.ncsa.myproxy.oauth2;

import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.ClaimSource;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.oa4mp.delegation.server.ServiceTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.server.request.ATRequest;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.AuthorizationGrantImpl;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.impl.RefreshTokenImpl;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.OA2TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.jwt.FlowStates;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.AGRequest2;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.OIDCServiceTransactionInterface;
import edu.uiuc.ncsa.oa4mp.delegation.oa2.server.RTIRequest;
import edu.uiuc.ncsa.security.util.TestBase;
import net.sf.json.JSONObject;
import org.junit.Test;

import java.util.Collection;
import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 10/3/13 at  4:29 PM
 */
public class TF2Test extends TestBase {
    @Test
    public void testTokens() throws Exception {
        OA2TokenForge tf2 = new OA2TokenForge("https://test/server/");
        AGRequest2 agRequest = new AGRequest2(null, 15 * 60 * 1000L);
        AuthorizationGrantImpl ag = tf2.createToken(agRequest);
        System.out.println(ag);
        FakeST fakeST = new FakeST(BasicIdentifier.newID(ag.getURIToken()));

        System.out.println(ag);
        AccessTokenImpl at = tf2.createToken(new ATRequest(null, fakeST));
        System.out.println(at);
        RefreshTokenImpl rt = tf2.createToken(new RTIRequest(fakeST, true));
        System.out.println(rt);
        try {
            tf2.getVerifier();
        } catch (UnsupportedOperationException gx) {
            assert true;
        }
        System.out.println(tf2.getRefreshToken());
    }

    public static class FakeST extends ServiceTransaction implements OIDCServiceTransactionInterface {
        @Override
        public JSONObject getATData() {
            return null;
        }

        @Override
        public void setATData(JSONObject atData) {

        }

        @Override
        public List<String> getResource() {
            return null;
        }

        @Override
        public void setResource(List<String> resource) {

        }

        @Override
        public void setClaimsSources(List<ClaimSource> sources) {

        }

        public FakeST(Identifier identifier) {
            super(identifier);
        }

        @Override
        public FlowStates getFlowStates() {
            return null;
        }

        @Override
        public void setFlowStates(FlowStates flowStates) {

        }

        @Override
        public JSONObject getUserMetaData() {
            return new JSONObject();
        }

        @Override
        public void setUserMetaData(JSONObject claims) {

        }
        String idtID = null;
        @Override
        public String getIDTokenIdentifier() {
            return idtID;
        }

        @Override
        public void setIDTokenIdentifier(String idTokenIdentifier) {
            idtID = idTokenIdentifier;
        }

        @Override
        public Collection<String> getScopes() {
            return null;
        }

        @Override
        public void setScopes(Collection<String> scopes) {

        }

        @Override
        public String getProxyId() {
            return null;
        }

        @Override
        public void setProxyId(String proxyId) {

        }

        @Override
        public JSONObject getProxyState() {
            return null;
        }

        @Override
        public void setProxyState(JSONObject proxyState) {

        }

        @Override
        public List<String> getAudience() {
            return null;
        }

        @Override
        public void setAudience(List<String> audience) {

        }

        @Override
        public JSONObject getExtendedAttributes() {
            return null;
        }

        @Override
        public void setExtendedAttributes(JSONObject xas) {

        }

        @Override
        public long getAccessTokenLifetime() {
            return 15 * 60 * 1000L;
        }

        @Override
        public long getRefreshTokenLifetime() {
            return 11 * 24 * 60 * 1000L;
        }

        @Override
        public long getAuthzGrantLifetime() {
            return 15 * 60 * 1000L;
        }
    }
}
