package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage;

import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.servlet.RFC8628State;
import edu.uiuc.ncsa.security.core.Identifiable;

import java.util.List;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/23/21 at  7:00 AM
 */
public interface RFC8628Store<V extends Identifiable> {
    List<RFC8628State> getPending();
    V getByUserCode(String userCode);
    boolean hasUserCode(String userCode);
}
