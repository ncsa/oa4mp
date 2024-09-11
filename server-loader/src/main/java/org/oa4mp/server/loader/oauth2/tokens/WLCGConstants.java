package org.oa4mp.server.loader.oauth2.tokens;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 7/27/20 at  3:16 PM
 */
public interface WLCGConstants {
    String STORAGE_READ = "storage.read";
    String STORAGE_CREATE = "storage.create";
    String STORAGE_MODIFY = "storage.modify";
    String STORAGE_STAGE = "storage.stage";

    String COMPUTE_READ = "compute.read";
    String COMPUTE_MODIFY = "compute.modify";
    String COMPUTE_CREATE = "compute.create";
    String COMPUTE_CANCEL = "compute.cancel";

    String GROUPS_TAG = "wlcg.groups";
    String WLCG_TAG = "wlcg";
    String WLCG_VERSION_TAG = "wlcg.ver";
    String WLCG_VERSION_1_0 = "1.0";

    String EDUPERSON_ASSURANCE= "eduperson_assurance";
}
