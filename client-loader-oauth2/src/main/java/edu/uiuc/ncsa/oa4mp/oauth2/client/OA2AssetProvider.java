package edu.uiuc.ncsa.oa4mp.oauth2.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.Asset;
import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.AssetProvider;
import edu.uiuc.ncsa.security.core.Identifier;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 3/28/14 at  1:51 PM
 */
public class OA2AssetProvider<V extends OA2Asset> extends AssetProvider<V> {
    @Override
    public Asset get(Identifier identifier) {
        return new OA2Asset(identifier);
    }
}
