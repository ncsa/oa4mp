package org.oa4mp.server.admin.install;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * This is a utility class that has the logic of how to make a list of only
 * the files in the current distribution. It takes one argument, the
 * top-level directory of the distritution.
 * <p>Created by Jeff Gaynor<br>
 * on 5/25/24 at  6:41 AM
 */
public class ListDistroFiles {
    public static final String FILE_LIST = "file_list.txt";
    public static final String DIR_LIST = "dir_list.txt";

    public static void main(String[] args) throws Throwable {
        if (args.length != 1) {
            System.err.println("List distribution files requires the directory of the distribution");
            System.exit(1);
        }
        File rootDirectory = new File(args[0]);
        if (!rootDirectory.exists()) {
            System.err.println("\"" + rootDirectory.getAbsolutePath() + "\" does not exist");
            System.exit(1);

        }
        if (!rootDirectory.isDirectory()) {
            System.err.println("\"" + rootDirectory.getAbsolutePath() + "\" is not a directory");
            System.exit(1);
        }
        ListDistroFiles listDistroFiles = new ListDistroFiles();
        listDistroFiles.runnit(rootDirectory);
    }

    protected void runnit(File rootDirectory) throws IOException {
        createFileList(rootDirectory);
        writeFiles(rootDirectory, dirList, DIR_LIST);
        writeFiles(rootDirectory, fileList, FILE_LIST);
    }
    

    List<String> fileList;
    List<String> dirList;

    int rootPathLength;

    protected void say(Object x) {
        System.out.println(x.toString());
    }

    /**
     * Create a file list. This is aware of the structure of the distribution and skips
     * certain things. It only has the exact files -- no directories -- relative
     * to the distribution and normalized. Later this list is used to get them
     * as resources from the class loader.
     *
     * @param rootDirectory
     * @return
     */
    protected void createFileList(File rootDirectory) {
        fileList = new ArrayList<>();
        dirList = new ArrayList<>();
        rootPathLength = rootDirectory.getAbsolutePath().toString().length();
        List<String> excludeList = Arrays.asList("installer.mf", "Installer.class", "qdl-installer.jar");
        File[] files = rootDirectory.listFiles();
        for (File f : files) {
            if (excludeList.contains(f.getName())) {
                continue;
            }
            if (f.isDirectory()) {
                recurse(f);
            } else {
                // trick is to get all relative to root directory
                fileList.add(f.getAbsolutePath().substring(rootPathLength));
            }
        }
    }

    protected void recurse(File rootDirectory) {
        String relativeDirPath = rootDirectory.getAbsolutePath().substring(rootPathLength);
        if(relativeDirPath.startsWith("/edu")){
            // do nothing if it starts with /edu -- that just contains the Installer.class
            // which should never end up in the user's distribution.
            return;

        }
        dirList.add(rootDirectory.getAbsolutePath().substring(rootPathLength));
        File[] files = rootDirectory.listFiles();
        for (File f : files) {
            if (f.isDirectory()) {
                recurse(f);
            } else {
                fileList.add(f.getAbsolutePath().substring(rootPathLength));
            }
        }
    }

    protected void writeFiles(File rootDir, List<String> targetList, String targetFilename) throws IOException {
        StringBuilder stringBuilder = new StringBuilder();
        for (String dir : targetList) {
            stringBuilder.append(dir + "\n");
        }
        File targetFile = new File(rootDir, targetFilename);
        if(targetFile.exists()){
            targetFile.delete();
        }
        FileWriter fileWriter = new FileWriter(targetFile);
        fileWriter.write(stringBuilder.toString());
        fileWriter.flush();
        fileWriter.close();
    }
}
