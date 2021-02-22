package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.vo;

import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 12/14/20 at  8:54 AM
 */
public interface VOStore<V extends VirtualOrganization> extends Store<V> {
     MapConverter<V> getMapConverter();

}
