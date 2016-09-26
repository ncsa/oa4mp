package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.util.MyLoggingFacade;
import edu.uiuc.ncsa.security.util.cli.CommonCommands;
import edu.uiuc.ncsa.security.util.cli.InputLine;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/13 at  2:38 PM
 */
public class CopyCommands extends CommonCommands {
    String configFile;

    public CopyCommands(MyLoggingFacade logger, CopyTool copyTool, CopyToolVerifier verifier, String configFile) {
        super(logger);
        this.configFile = configFile;
        this.copyTool = copyTool;
        this.verifier = verifier;
    }


    public static final String VERIFY_OPTION = "-verify";

    @Override
    public String getPrompt() {
        return "  copy>";
    }

    protected void showCpHelp() {
        sayi("This command copies one store to another. At the end of this operation the");
        sayi("target store will be identical to the source, so yes, this will destroy the target");
        sayi("store.Syntax is\n");
        sayi("cp source target [" + VERIFY_OPTION + "]\n");
        sayi("where source and target are the names of configurations in the currently active configuration file");
        sayi("If you supply the verify option, then the target and source content will be checked against each other");
        sayi("to ensure they match. Warning:This can be slow, depending on the store involved.");
        sayi("If you need more functionality (such as the ability to use this with multiple configuration files)");
        sayi("then you should use the dedicated command line tool for this.");

    }

    public void cp(InputLine inputLine) throws Throwable {
        if (showHelp(inputLine)) {
            showCpHelp();
            return;
        }

        if (inputLine.size() < 3) {
            sayi("Sorry, you don't have enough arguments for me to be sure what you want.");
            showCpHelp();
            return;
        }
        String source = inputLine.getArg(1);
        String target = inputLine.getArg(2);
        boolean verify = false;
        if (inputLine.size() == 4) {
            verify = inputLine.getArg(3).equals(VERIFY_OPTION);
        }
        sayi("Verification is " + (verify ? "on" : "off"));
        info("Copy tool, verifications " + (verify ? "on" : "off"));
        sayi2("Are you sure you want to copy  " + source + " to " + target + ", erasing the current contents of " + target + "? [y|n]");
        if (!isOk(readline())) {
            sayi("User cancelled. aborting copy with no changes.");
            info("User aborted copy.");
            return;
        }
        // so now we do surgery on the command line...
        String[] args = new String[]{
                "-" + CopyTool.CONFIG_FILE_OPTION, configFile,
                "-" + CopyTool.SOURCE_CONFIG_NAME_OPTION, inputLine.getArg(1),
                "-" + CopyTool.TARGET_CONFIG_NAME_OPTION, inputLine.getArg(2),
                "-" + CopyTool.VERBOSE_OPTION}; //make sure it talks to the user.
        getCopyTool().run(args);
        if(verify){
            getVerifier().verifyStores(getCopyTool().getSourceEnv(), getCopyTool().getTargetEnv());
        }
        sayi("done!");
    }

    CopyToolVerifier verifier;
    public CopyToolVerifier getVerifier(){
        if(verifier == null){
            verifier = new CopyToolVerifier();
        }
        return verifier;
    }
    CopyTool copyTool;

    public CopyTool getCopyTool() {
        if (copyTool == null) {
            copyTool = new CopyTool();
        }
        return copyTool;
    }

    public void setCopyTool(CopyTool copyTool) {
        this.copyTool = copyTool;
    }
}
