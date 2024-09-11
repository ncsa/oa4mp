package org.oa4mp.delegation.client.test.common.storage;

import org.oa4mp.delegation.common.token.impl.TokenImpl;

import java.net.URI;

/**
 * <p>Created by Jeff Gaynor<br>
 * on May 6, 2011 at  3:18:38 PM
 */
public class FakeTokenImpl extends TokenImpl {

    @Override
    public String toString() {
        return "FakeTokenImpl{" +
                "token='" + getToken() + '\'' +
                '}';
    }



    public FakeTokenImpl(URI token) {
        this(token.toString());
    }

    public FakeTokenImpl(String token) {
        super(URI.create(token));
    }


}
