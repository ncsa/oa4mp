package edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.types;

import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.SAT;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.things.Thing;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/22/16 at  10:43 AM
 */
public class Type extends Thing{
    public Type() {
        this(SAT.KEYS_TYPE);
    }

    public Type(String value) {
        super(value);
    }
}
