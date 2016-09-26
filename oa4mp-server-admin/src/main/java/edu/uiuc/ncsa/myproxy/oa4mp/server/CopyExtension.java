package edu.uiuc.ncsa.myproxy.oa4mp.server;

/**
 * This allows tools to re-use copy routines from custom stores. Set one in your {@link CopyTool}
 * and it will be invoked after all other stores are copied.
 * <p>Created by Jeff Gaynor<br>
 * on 3/25/15 at  3:08 PM
 */
public class CopyExtension {
    /**
     * Takes the number of records copied so far and returns this plus the number of
     * records copied. This value is the total number of records copied from all stores
     * total.
     *
     * @param totalRecs
     * @return
     */
    public int copy(int totalRecs) {
        return totalRecs;
    }
}
