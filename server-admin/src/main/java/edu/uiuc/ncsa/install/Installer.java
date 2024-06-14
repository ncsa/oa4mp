package edu.uiuc.ncsa.install;

/**
 * <p>Created by Jeff Gaynor<br>
 * on 6/11/24 at  11:33 AM
 */

import edu.uiuc.ncsa.oa4mp.OA4MPVersion;
import edu.uiuc.ncsa.qdl.install.ListDistroFiles;

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.*;

/**
 * Really simple installer. This basically just copies stuff that has been set up in the
 * create_installer.sh script, so chances are excellent if you need to change the installer,
 * you should be looking there.<br/><br/>
 * This gets copied to your jar and will just copy everything in the jar to
 * a given directory (including sub directories). So make the tree you want, jar it up with this class
 * and run it.
 * <h2>Caveat for changing this class</h2>
 * This is a completely standalone class -- no dependencies but plain Old Java -- because
 * otherwise you have to manage dependencies (might involve writing your own class loader!)
 * for this installer program which can get very hard. The idea is that this is a lean,
 * single class. Even inheritance doesn't work.
 * <p>Created by Jeff Gaynor<br>
 * on 3/30/20 at  7:23 AM
 */
public class Installer {
    protected void trace(String message) {
        if (isDebugOn()) {
            say(message);
        }
    }

    public boolean isDebugOn() {
        return debugOn;
    }

    public void setDebugOn(boolean debugOn) {
        this.debugOn = debugOn;
    }

    boolean debugOn = false;


    public static void main(String[] args) {
        edu.uiuc.ncsa.install.Installer installer = new edu.uiuc.ncsa.install.Installer();
        try {
            installer.runnit2(args);
        } catch (Throwable t) {
            installer.say(t.getMessage());
            if (installer.isDebugOn()) {
                t.printStackTrace();
            }
        }
    }


    protected void runnit2(String[] args) throws Throwable {
        say("OA4MP installer version " + OA4MPVersion.VERSION_NUMBER);
        argMap = new HashMap<>();
        setupArgMap(args);
        if (isShowHelp()) {
            showHelp();
            return;
        }
        if (getOperation().startsWith("-")) {
            say("unknown operation \"" + getOperation() + "\"");
            return;
        }
        setDebugOn(is(DEBUG_FLAG));

        if (isList()) {
            doListFiles();
            return;
        }
        if (isInstall() && isUpgrade()) {
            say("sorry, you cannot specify both an upgrade and an install");
            return;
        }
        if ((isInstall() || isUpgrade()) && isRemove()) {
            say("sorry, you cannot specify both an removing QDL and an install/upgrade");
            return;
        }
        if (isRemove()) {
            doRemove();
            return;
        }
        File rootDir = checkRootDir(getRootDir(), isUpgrade());
        if (rootDir == null) {
            return;
        }
        setupTemplates();
        if (isInstall()) {
            doInstall();
        }
        if (isUpgrade()) {
            doUpgrade();
        }
    }

    protected void doUpgrade() throws Exception {
        File rootDir = getRootDir();
        if (isOA4MP()) {
            upgradeOA4MP(rootDir);
        }

    }

    protected void doInstall() throws Exception {
        File rootDir = getRootDir();
        if (isOA4MP()) {
            installOA4MP(rootDir);
            say("Done! You should add");
            say("   export OA4MP_HOME=\"" + rootDir.getAbsolutePath() + "\"");
            say("to your environment and");
            say("   $OA4MP_HOME" + File.separator + "bin\"");
            say("to your PATH");
        }

    }

    protected void doRemove() throws IOException {
        if (isOA4MP()) {
            uninstallOA4MP(getRootDir());
        }

    }

    protected void uninstallOA4MP(File rootDir) {
        if (rootDir == null) {
            say("you must explicitly specify the directory to be removed. exiting...");
        } else {
            nukeDir(rootDir);
            rootDir.delete(); //adios muchacho
            say(rootDir + " and all of its subdirectories have been removed.");
        }
    }


    static protected final String UPGRADE_FLAG = "-u";
    static protected final String UPGRADE_OPTION = "upgrade";
    static protected final String HELP_FLAG = "--help";
    static protected final String HELP_OPTION = "help";
    static protected final String DIR_ARG = "-dir";
    static protected final String DEBUG_FLAG = "-debug";
    static protected final String INSTALL_OPTION = "install";
    static protected final String LIST_OPTION = "list";
    static protected final String REMOVE_OPTION = "remove";
    static protected final String OA4MP_FLAG = "-oa4mp";
    static protected final String ALL_FLAG = "-all";
    static protected final String HOST_FLAG = "-host";
    static protected final String PORT_FLAG = "-port";

    static List<String> allOps = Arrays.asList(UPGRADE_OPTION, REMOVE_OPTION, HELP_OPTION, INSTALL_OPTION, LIST_OPTION);
    protected String host = "localhost";
    protected int port = 9443;

    private void showHelp() {
        say("=================================================================");
        say("java -jar oa4mp-installer.jar install operation arguments* flags*");
        say("=================================================================");
        say("This will install OA4MP to your system. Options are:");
        say("(none) = same as help");
        say(INSTALL_OPTION + " = install");
        say(UPGRADE_OPTION + " = upgrade");
        say(REMOVE_OPTION + " = remove");
        say(HELP_OPTION + " = show help and exit. Note you can also use the flag " + HELP_FLAG);
        say(LIST_OPTION + " = list all the files in the distribution. Nothing is done.");
        say("--------------");
        say("arguments are:");
        say(DIR_ARG + " root = install to the given directory. If omitted, you will be prompted.");
        say("--------------");
        say("Flags are:");
        say(DEBUG_FLAG + " = debug mode -- print all messages from the installer as it runs. This is quite verbose.");
        say(HELP_FLAG + " = this help message");
        say(OA4MP_FLAG + " = install support for OA4MP");
        say(ALL_FLAG + " = do all components");
        say(HOST_FLAG + " = the host for the service. Default is localhost");
        say(PORT_FLAG + " = the port for the service. Default is 9443. If you set it to -1, no port is used.");
        say("");
        say("E.g.");
        say("A fresh install, specifying the machine and port. This assumes OA4MP_HOME has been set.");
        say("The port is set to -1 meaning that no port will be specified for the endpoints. This is used, ");
        say("e.g., if this is behind another server (like Apache) that forwards requests.");
        say(getClass().getSimpleName() + " " + INSTALL_OPTION + " " + ALL_FLAG + " " + DIR_ARG + " $OA4MP_HOME " + HOST_FLAG + " issuer.bgsu.edu" + PORT_FLAG + " -1");
        say("\n\nExample of doing an upgrade");
        say(getClass().getSimpleName() + " " + UPGRADE_OPTION + " " + ALL_FLAG + " " + DIR_ARG + " $OA4MP_HOME");
        say("This upgrades all components, but does not touch any .xml (config) files or scripts.\n");
    }

    Map<String, String> templates;

    /**
     * Sets up the templates for replacement. Run this <b>after</b> {@link #setupArgMap(String[])}.
     *
     * @throws IOException
     */
    protected void setupTemplates() throws IOException {
        templates = new HashMap<>();
        templates.put("${OA4MP_HOME}", getRootDir().getCanonicalPath() + File.separator);
        String h = getHost();
        if (hasPort()) {
            h = h + ":" + getPort();
        }
        templates.put("${OA4MP_HOST}", h);
    }

    File userHome = null;

    protected File getUserHome() {
        if (userHome == null) {
            userHome = new File(System.getProperty("user.home"));
        }
        return userHome;
    }


    /**
     * For upgrades. If the directory does not exist, create it.
     * Return false if the directory does not exist.
     *
     * @param dir
     * @return
     */
    protected boolean checkUpgradeDir(File dir) {
        trace("checking if dir exists for " + dir);
        if (!dir.exists()) {
            if (!dir.mkdir()) {
                trace("  nope");
                return false;
            }

        }
        trace("  yup");

        return true;
    }

    /**
     * Remove the contents of the  directory. At the end of this,
     * the directory is empty. It does not delete the directory,
     * however
     *
     * @param dir
     */
    protected void nukeDir(File dir) {
        if (!dir.isDirectory()) return; //
        File[] contents = dir.listFiles();
        for (File f : contents) {
            trace("found " + f);

            if (f.isFile()) {
                trace("   deleting file:" + f);
                f.delete();
            }
            if (f.isDirectory()) {
                trace("   deleting dir:" + f);
                nukeDir(f);
                f.delete();
            }
        }
    }


    protected void doListFiles() throws Exception {
        say("files in this distribution");
        say("--------------------------");
        InputStream is = getClass().getResourceAsStream("/" + ListDistroFiles.FILE_LIST); // start with something we know is there
        List<String> fileList = isToList(is);
        for (String file : fileList) {
            say(file);
        }
    }

    protected List<String> isToList(InputStream inputStream) throws IOException {
        // This has been ingested as a collection of lines. Convert to list
        String text = new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        List<String> myList = new ArrayList<String>(Arrays.asList(text.split("\\r?\\n")));
        return myList;
    }

    /**
     * Overwrites (but does not delete) files and will make more complex paths.
     * This allows for upgrading much older QDL installs that might have
     * different or missing (e.g. vim support) directories.
     *
     * @throws Exception
     */
    protected void upgradeOA4MP(File rootDir) throws Exception {
        InputStream is = getClass().getResourceAsStream("/" + ListDistroFiles.FILE_LIST); // start with something we know is there
        List<String> fileList = isToList(is);
        setupDirs(rootDir);

        for (String file : fileList) {
            if (file.startsWith("/bin") || (file.startsWith("/etc") && !file.endsWith(".sql"))) {
                // On upgrades, do NOT touch the bin or etc config files  since the files are
                // edited in the installation.
                continue;
            }
            File f = new File(rootDir.getAbsolutePath() + file);
            if (f.exists()) {
                f.delete();
            }
            trace("  " + file + " --> " + f.getCanonicalPath());
            cp(file, f);
            if (file.endsWith(".qdl")) {
                doSetupScript(f);
            }
        }
    }

    private void setupDirs(File rootDir) throws IOException {
        InputStream is;
        is = getClass().getResourceAsStream("/" + ListDistroFiles.DIR_LIST); // start with something we know is there
        List<String> dirList = isToList(is);
        for (String dir : dirList) {
            File f = new File(rootDir.getAbsolutePath() + dir);
            trace("checking dir " + dir + " --> " + f.getCanonicalPath());
            if (!f.exists()) {
                f.mkdirs();
            }
        }
    }

    /**
     * gets the resourceName as a stream and copies it to the physical target
     * file.
     *
     * @param resourceName
     * @param target
     * @throws IOException
     */
    protected void cp(String resourceName, File target) throws IOException {
        if (target.isDirectory()) {
            trace("Skipping directory " + target);
            return;
        }
        InputStream is = getClass().getResourceAsStream(resourceName); // start with something we know is there
        Files.copy(is, target.toPath()); // binary copy.
    }


    protected void installOA4MP(File rootDir) throws Exception {
        InputStream is = getClass().getResourceAsStream("/" + ListDistroFiles.FILE_LIST); // start with something we know is there
        List<String> fileList = isToList(is);
        trace("starting install...");
        setupDirs(rootDir);

        for (String file : fileList) {
            File f = new File(rootDir.getAbsolutePath() + file);
            if (f.exists()) {
                f.delete();
            }
            trace("  " + file + " --> " + f.getCanonicalPath());
            cp(file, f);
            if (file.startsWith("/bin/")) {
                trace("   setting up oa4mp script to be executable:" + file);
                doSetupExec(f);
            }
            if (file.startsWith("/etc/") && file.endsWith(".xml")) {
                // process xml config files in /etc only.
                trace("  setting up basic configuration");
                processTemplates(f);
            }
        }
    }


    /**
     * Read the executable file (the one they invoke to run QDL) and set the root directory in it,
     * then set it to be executable.
     *
     * @param f
     */
    private void doSetupExec(File f) throws IOException {
        List<String> lines = Files.readAllLines(f.toPath());
           trace("      read:" + lines.size() + " lines");
        for (int i = 0; i < lines.size(); i++) {
            lines.set(i, doReplace(lines.get(i)));
            trace("  writing: \"" + lines.get(i) + "\"");

        }
        Files.write(f.toPath(), lines, Charset.defaultCharset());
        trace("setting " + f.getAbsolutePath() + " to executable");
        f.setExecutable(true);
    }

    public static String SHEBANG = "#!";

    /**
     * Files that start with a shebang (#!) should be set executable.
     *
     * @param f
     * @throws IOException
     */
    private void doSetupScript(File f) throws IOException {
        trace("setting up script: " + f.getAbsolutePath());
        List<String> lines = Files.readAllLines(f.toPath());
        for (String line : lines) {
            if (!line.isBlank()) {
                if (line.trim().startsWith(SHEBANG)) {
                    f.setExecutable(true);
                    trace("   >> was set executable!");
                }
                // only sniff first non-blank line. Don't care about anything else,
                // so don't process the rest of the file.
                return;
            }
        }

    }

    /**
     * Does all of the template replacements in a line.
     * @param currentLine
     * @return
     */
    protected String doReplace(String currentLine) {
        for (String key : templates.keySet()) {
            if (currentLine.contains(key)) {
                trace("replacing key = " + key);
                trace("   with value = " + templates.get(key));
                currentLine = currentLine.replace(key, templates.get(key));
            }
        }
        return currentLine;
    }

    private void processTemplates(File f) throws IOException {
        List<String> lines = Files.readAllLines(f.toPath());
        for (int i = 0; i < lines.size(); i++) {
            lines.set(i, doReplace(lines.get(i)));
        }
        Files.write(f.toPath(), lines, Charset.defaultCharset());
    }

    /**
     * Prompts for the right directory, if missing, and then it will check if various
     * directories exist. If this returns false, then the install cannot
     * proceed, because, e.g., they request an upgrade but no base install
     * exists.
     *
     * @return
     * @throws Exception
     */
    protected File checkRootDir(File rootDir, boolean upgrade) throws Exception {
        if (rootDir == null) {
            String lineIn = readline("Enter the target directory for the QDL installer:");
            rootDir = new File(lineIn);
        }
        if (upgrade) {
            if (!rootDir.exists()) {
                say("Sorry, but that directory does not exist so no upgrade can be done. Exiting...");
                return null;
            }
        } else {
            if (rootDir.exists()) {
                if (rootDir.list().length != 0) {
                    say("This exists and is not empty. This will only install to an empty/non-existent directory.\nDid you mean " + UPGRADE_OPTION + "?");
                }
                return null;
            }
            trace("creating directories for root path");
            Files.createDirectories(rootDir.toPath());
        }
        return rootDir;
    }


    protected BufferedReader getBufferedReader() {
        if (bufferedReader == null) {
            bufferedReader = new BufferedReader(new InputStreamReader(System.in));
        }
        return bufferedReader;
    }


    BufferedReader bufferedReader;

    public String readline(String prompt) throws Exception {
        System.out.print(prompt);
        return getBufferedReader().readLine();
    }

    protected void say(String x) {
        System.out.println(x);
    }

    HashMap<String, Object> argMap;
    public String operationKey = "operation";
    public static String NO_PORT = "-1";

    protected void setupArgMap(String[] args) {
        argMap = new HashMap<>();

        if (args.length == 0
                || args[0].equals(HELP_OPTION)
                || args[0].equals(HELP_FLAG)) {
            // if there are no options or the only one is help, just print help
            argMap.put(HELP_OPTION, true);
            return;
        }
        argMap.put(operationKey, args[0]);
        for (int i = 1; i < args.length; i++) {
            String arg = args[i];
            switch (arg) {
                case HELP_FLAG:
                    argMap.put(HELP_OPTION, true);
                    return;
                case DEBUG_FLAG:
                    argMap.put(DEBUG_FLAG, true);
                    break;
                case DIR_ARG:
                    if ((i + 1) < args.length) {
                        // if this is the very last argument on the line, skip it
                        if (args[i + 1].startsWith("-")) {
                            throw new IllegalArgumentException("missing directory");
                        }
                        argMap.put(DIR_ARG, new File(args[++i]));
                    }
                    break;
                case ALL_FLAG:
                    argMap.put(ALL_FLAG, true);
                    break;
                case OA4MP_FLAG:
                    argMap.put(OA4MP_FLAG, true);
                    break;
                case HOST_FLAG:
                    argMap.put(HOST_FLAG, args[i]);
                    break;
                case PORT_FLAG:
                    argMap.put(PORT_FLAG, args[i]);
                    break;
            }
        }
        if (!isShowHelp()) {
            if (!allOps.contains(getOperation())) {
                throw new IllegalArgumentException("unknown operation \"" + getOperation() + "\"");
            }
        }
    }

    protected boolean hasPort() {
        if (!argMap.containsKey(PORT_FLAG)) return true; // means they get the default
        return !argMap.get(PORT_FLAG).equals(NO_PORT);
    }

    protected String getHost() {
        if (argMap.containsKey(HOST_FLAG)) {
            return (String) argMap.get(HOST_FLAG);
        }
        return host;
    }

    protected int getPort() {
        if (argMap.containsKey(PORT_FLAG)) {
            return Integer.parseInt((String) argMap.get(PORT_FLAG));
        }
        return port;
    }

    // Help functions. These SHOULD be in another class, but that would mean writing
    // a separate classloader for the executable jar -- way too much work

    /**
     * Checks that the key is a boolean
     * @param key
     * @return
     */
    public Boolean is(String key) {
        if (!argMap.containsKey(key)) return false;
        return (Boolean) argMap.get(key);
    }

    public File getRootDir() {
        if (!argMap.containsKey(DIR_ARG)) return null;
        return (File) argMap.get(DIR_ARG);
    }

    public boolean isInstall() {
        return getOperation().equals(INSTALL_OPTION);
    }

    public boolean isRemove() {
        return getOperation().equals(REMOVE_OPTION);
    }

    public boolean isUpgrade() {
        return getOperation().equals(UPGRADE_OPTION);
    }

    public boolean isShowHelp() {
        return is(HELP_OPTION) || getOperation().equals(HELP_OPTION);
    }

    public boolean isList() {
        return getOperation().equals(LIST_OPTION);
    }

    public boolean hasRootDir() {
        return getRootDir() != null;
    }

    public String getOperation() {
        return (String) argMap.get(operationKey);
    }

    public boolean isAll() {
        return is(ALL_FLAG);
    }


    public boolean isOA4MP() {
        return is(OA4MP_FLAG) || is(ALL_FLAG);
    }
protected void download(URL url, File targetFile) throws IOException {
    HttpURLConnection connection = (HttpURLConnection) url.openConnection();
    DataInputStream dis = new DataInputStream(connection.getInputStream());
    FileOutputStream fos = new FileOutputStream(targetFile);
    byte[] buffer = new byte[1024];
    int offset =0;
    int bytes;
    while(0 < (bytes = dis.read(buffer, offset, buffer.length)) ){
        fos.write(buffer, 0, bytes);
    }
    fos.close();
    dis.close();
}
}
