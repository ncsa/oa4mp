package edu.uiuc.ncsa.oa4mp.client.installer;

import edu.uiuc.ncsa.security.installer.WebInstaller;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/19/24 at  7:23 AM
 */
public class OA4MPClientInstaller extends WebInstaller {
    @Override
    protected String getSetup() {
        return "/oa4mp/setup.yaml";
    }
}
