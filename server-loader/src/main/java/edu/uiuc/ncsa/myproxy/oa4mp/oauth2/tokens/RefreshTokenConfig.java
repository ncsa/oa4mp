package edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.tokens.BasicRefreshTokenHandler.REFRESH_TOKEN_DEFAULT_HANDLER_TYPE;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/5/20 at  10:56 AM
 */
public class RefreshTokenConfig extends AbstractCommonATandRTConfig {
    @Override
    public String getType() {
        if(type == null){
            type = REFRESH_TOKEN_DEFAULT_HANDLER_TYPE;
        }
        return type;
    }
}
