package org.oa4mp.server.loader.oauth2.tokens;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 8/5/20 at  10:56 AM
 */
public class RefreshTokenConfig extends AbstractCommonATandRTConfig {
    @Override
    public String getType() {
        if(type == null){
            type = BasicRefreshTokenHandler.REFRESH_TOKEN_DEFAULT_HANDLER_TYPE;
        }
        return type;
    }
}
