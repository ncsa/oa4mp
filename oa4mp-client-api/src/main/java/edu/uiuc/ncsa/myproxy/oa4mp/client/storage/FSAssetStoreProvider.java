package edu.uiuc.ncsa.myproxy.oa4mp.client.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.client.ClientXMLTags;
import edu.uiuc.ncsa.security.core.configuration.provider.CfgEvent;
import edu.uiuc.ncsa.security.storage.FSProvider;
import edu.uiuc.ncsa.security.storage.data.MapConverter;
import org.apache.commons.configuration.tree.ConfigurationNode;

import java.io.File;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 1/31/13 at  10:24 AM
 */
public class FSAssetStoreProvider extends FSProvider<FSAssetStore> {
    public FSAssetStoreProvider(ConfigurationNode config,  AssetProvider assetProvider, MapConverter converter) {
        super(config, ClientXMLTags.FILE_STORE, ClientXMLTags.ASSET_STORE, converter);
        this.assetProvider = assetProvider;
    }

    protected AssetProvider assetProvider;

    @Override
       public Object componentFound(CfgEvent configurationEvent) {
           if (checkEvent(configurationEvent)) {
               return super.componentFound(configurationEvent);
           }
           return null;
       }

       @Override
       protected FSAssetStore produce(File dataPath, File indexPath) {
           return new FSAssetStore(dataPath, indexPath, assetProvider, converter);
       }
}
