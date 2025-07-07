package org.oa4mp.client.installer;


import org.oa4mp.installer.AbstractInstaller;

import java.io.IOException;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/19/24 at  7:23 AM
 */
public class OA4MPClientInstaller extends AbstractInstaller {

    public static void main(String[] args) {
        try {
            OA4MPClientInstaller oa4MPClientInstaller = new OA4MPClientInstaller();
            boolean doProcessing = oa4MPClientInstaller.init(args);
            if (oa4MPClientInstaller.getArgMap().isShowHelp()) {
                oa4MPClientInstaller.showHelp();
                return;
            }
            if (doProcessing) {
                oa4MPClientInstaller.process();
                if(oa4MPClientInstaller.getArgMap().isInstall()){
                    oa4MPClientInstaller.say(oa4MPClientInstaller.getMessage("/oa4mp/success.txt"));
                }
            }
            oa4MPClientInstaller.shutdown();

        } catch (Throwable t) {
            t.printStackTrace();
        }
    }

    @Override
    protected String getDerbySetupScriptPath() {
        return getTemplates().get("${OA4MP_HOME}") + "etc/client-derby.sql";

    }

    @Override
    protected void printMoreExamplesHelp() throws IOException {
        say("\n\nExample of preparing an extension file for preprocessing. ");
        say("This is used if you want to apply scripts to the server right after boot, for instance.");
        say("Your file should use the template of ${OA4MP_HOME} every place it needs to refer to the");
        say("(new) installation. So the example might be a QDL ini file that needs the path to the current");
        say("server configuration to do some setup before starting the server:");
        say("[cfg]");
        say("file := '${OA4MP_HOME}etc/cfg.xml';");
        say("name := 'default';");
    }
}
