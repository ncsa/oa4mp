package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.client.AssetStoreTest;
import edu.uiuc.ncsa.myproxy.client.ClientTestStoreUtil;
import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetStore;
import edu.uiuc.ncsa.security.delegation.token.AccessToken;
import edu.uiuc.ncsa.security.delegation.token.RefreshToken;
import edu.uiuc.ncsa.security.delegation.token.impl.AccessTokenImpl;
import edu.uiuc.ncsa.security.oauth_2_0.OA2RefreshTokenImpl;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/28/14 at  11:27 AM
 */
public class Client2AssetStoreTest extends AssetStoreTest {


    @Override
    public Asset storeTest(AssetStore store) throws Exception {
        OA2Asset asset = (OA2Asset) super.storeTest(store);
        AccessToken at = new AccessTokenImpl(URI.create("oa4mp:accessToken:/" + ClientTestStoreUtil.getRandomString()));
        RefreshToken rt = new OA2RefreshTokenImpl(URI.create("oa4mp:refreshToken:/" + ClientTestStoreUtil.getRandomString()));

        rt.setExpiresIn(1000000L);
        asset.setAccessToken(at);
        asset.setRefreshToken(rt);

        store.save(asset);

        OA2Asset OA2Asset = (OA2Asset) store.get(asset.getIdentifier());
        assert asset.getAccessToken().equals(OA2Asset.getAccessToken()) : "Failed to match access tokens. " +
                "Expected \"" + asset.getAccessToken() + "\" and got \"" + OA2Asset.getAccessToken() + "\"";

        RefreshToken rt2 = OA2Asset.getRefreshToken();
        assert rt.getToken().equals(rt2.getToken()) : "Failed to match refresh tokens. " +
                "Expected \"" + rt.getToken() + "\" and got \"" + rt2.getToken() + "\"";

        assert rt.getExpiresIn() == rt2.getExpiresIn() : "Failed to match refresh lifetime. " +
                "Expected \"" + rt.getExpiresIn() + "\" and got \"" + rt2.getExpiresIn() + "\"";


        return asset;
    }

}
