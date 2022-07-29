package edu.uiuc.ncsa.oa4mp.delegation.common.token;

import java.io.Serializable;

/**
 * General top-level object for tokens in a delegation system. All token are derivative of this.
 * Differing implementations may have to extend this.
 * <p>Created by Jeff Gaynor<br>
 * on Apr 28, 2011 at  9:39:23 AM
 */
public interface Token extends Serializable {
    /**
     * The token.
     *
     * @return
     */
    String getToken();


}
