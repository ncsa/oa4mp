package edu.uiuc.ncsa.myproxy.client;

import edu.uiuc.ncsa.myproxy.oa4mp.client.storage.*;
import edu.uiuc.ncsa.security.storage.sql.ConnectionPool;
import edu.uiuc.ncsa.security.storage.sql.mysql.MySQLConnectionParameters;
import edu.uiuc.ncsa.security.storage.sql.postgres.PostgresConnectionParameters;
import org.apache.commons.codec.binary.Base64;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.SecureRandom;
import java.util.Set;

/**
 * A utility that allows you to get each type of supported store for testing. Set the actual stores
 * in your test setup, then call the static methods here.
 * <p>Created by Jeff Gaynor<br>
 * on 3/31/14 at  2:22 PM
 */
public class ClientTestStoreUtil {
    static AssetStore memoryStore;
    static AssetStore postgresStore;
    static AssetStore mysqlStore;
    static AssetStore fileStore;

    public static AssetStore getFileStore() {
        return fileStore;
    }

    public static void setFileStore(AssetStore fileStore) {
        ClientTestStoreUtil.fileStore = fileStore;
    }

    public static AssetStore getMemoryStore() {
        return memoryStore;
    }

    public static void setMemoryStore(AssetStore memoryStore) {
        ClientTestStoreUtil.memoryStore = memoryStore;
    }

    public static AssetStore getMysqlStore() {
        return mysqlStore;
    }

    public static void setMysqlStore(AssetStore mysqlStore) {
        ClientTestStoreUtil.mysqlStore = mysqlStore;
    }

    public static AssetStore getPostgresStore() {
        return postgresStore;
    }

    public static void setPostgresStore(AssetStore postgresStore) {
        ClientTestStoreUtil.postgresStore = postgresStore;
    }

    static SecureRandom random = new SecureRandom();

    static public String getRandomString(int length) {
        byte[] b = new byte[length];
        random.nextBytes(b);
        return Base64.encodeBase64URLSafeString(b);
    }

    static public String getRandomString() {
        return getRandomString(32);
    }

    static public File createTempDir() throws IOException {
        File rootDir = null;

        if (System.getProperty("oa4mp:filestore:directory") == null) {
            Set<PosixFilePermission> perms =
                    PosixFilePermissions.fromString("rwxr-----");
            FileAttribute<Set<PosixFilePermission>> attr =
                    PosixFilePermissions.asFileAttribute(perms);
            Path dirPath = Files.createTempDirectory("oa4mp-", attr);

            rootDir = dirPath.toFile();
            System.out.println("Warning: no test file store configured. Creating random one " + rootDir);
        } else {
            rootDir = new File(System.getProperty("oa4mp:filestore:directory"));
        }
        return rootDir;

    }


    public static ConnectionPool setupPGConnectionPool(String databaseName, String schema) {
        if (System.getProperty("oa4mp:pg:username") == null || System.getProperty("oa4mp:pg:password") == null) {
            System.out.println("NOTE: You must set the username and password as properties for the PGStore test. Aborting...");
            return null;
        }
        AssetProvider ap = new AssetProvider();
        PostgresConnectionParameters x = new PostgresConnectionParameters(
                System.getProperty("oa4mp:pg:username"),
                System.getProperty("oa4mp:pg:password"),
                databaseName,
                schema,
                "localhost",
                5432,
                "org.postgresql.Driver",
                false, "");
        return new ConnectionPool(x);
    }

    public static ConnectionPool setupMySQLConnection(String databaseName, String schema) {
        if (System.getProperty("oa4mp:mysql:username") == null || System.getProperty("oa4mp:mysql:password") == null) {
            System.out.println("NOTE: You must set the username and password as properties for the MySQLStore test. Aborting...");
            return null;
        }
        AssetProvider ap = new AssetProvider();
        MySQLConnectionParameters x = new MySQLConnectionParameters(
                System.getProperty("oa4mp:mysql:username"),
                System.getProperty("oa4mp:mysql:password"),
                databaseName,
                schema,
                "localhost",
                3306,
                "com.mysql.jdbc.Driver",
                false,"");
        return new ConnectionPool(x);
    }

    public static AssetStore setupPGStore(String databaseName, String schema,
                                          AssetProvider ap,
                                          AssetConverter ac,
                                          AssetStoreTable table) {
        return new SQLAssetStore(setupPGConnectionPool(databaseName, schema),
                table, ap, ac);
    }

    public static AssetStore setupMySQLStore(String databaseName,
                                             String schema,
                                             AssetProvider ap,
                                             AssetConverter ac,
                                             AssetStoreTable table) {
        return new SQLAssetStore(setupMySQLConnection(databaseName, schema),
                table, ap, ac);
    }
}
