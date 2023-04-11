package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.claims.IDTokenHandler.ID_TOKEN_BASIC_HANDLER_TYPE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/1/20 at  3:18 PM
 */
public class IDTokenClientConfig extends AbstractPayloadConfig {
    @Override
    public String getType() {
        if(type == null){
             type = ID_TOKEN_BASIC_HANDLER_TYPE;
        }
        return type;
    }
}
