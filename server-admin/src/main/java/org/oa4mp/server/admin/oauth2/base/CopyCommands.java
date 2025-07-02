package org.oa4mp.server.admin.oauth2.base;

import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.CommonCommands2;
import edu.uiuc.ncsa.security.util.cli.InputLine;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 11/14/13 at  2:38 PM
 */
public class CopyCommands extends CommonCommands2 {
    String configFile;

    public CopyCommands(CLIDriver driver, CopyTool copyTool, CopyToolVerifier verifier, String configFile) throws Throwable{
        super(driver);
        this.configFile = configFile;
        this.copyTool = copyTool;
        this.verifier = verifier;
    }

    @Override
    public void about(boolean showBanner, boolean showHeader) {

    }

    @Override
    public void initialize() throws Throwable {

    }

    @Override
    public void load(InputLine inputLine) throws Throwable {

    }

    @Override
    public String getName() {
        return "copy";
    }

    public static final String VERIFY_OPTION = "-verify";

    @Override
    public String getPrompt() {
        return getName()+">";
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
        sayi("If you are using an SQL store, just use the built in database tools for that.");
        sayi("then you should also use the SQL store tool for that.");
        sayi("This is intended for moving e.g. one file store to another, or dumping an in-memory store to disk");
        sayi("i.e. moving between stores that do not have such tools.");

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
        String p = "Are you sure you want to copy  " + source + " to " + target + ", erasing the current contents of " + target + "? [y|n]";
        if (!isOk(readline(p))) {
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
