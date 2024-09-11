package org.oa4mp.client.loader;

import org.oa4mp.client.api.Asset;
import org.oa4mp.client.api.storage.AssetProvider;
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
