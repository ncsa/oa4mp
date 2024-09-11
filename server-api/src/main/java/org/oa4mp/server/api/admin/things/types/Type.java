package org.oa4mp.server.api.admin.things.types;

import org.oa4mp.server.api.admin.things.SAT;
import org.oa4mp.server.api.admin.things.Thing;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  10:43 AM
 */
public class Type extends Thing {
    public Type() {
        this(SAT.KEYS_TYPE);
    }

    public Type(String value) {
        super(value);
    }
}
