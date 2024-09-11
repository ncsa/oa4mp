package org.oa4mp.client.test;

import org.oa4mp.client.api.Asset;
import org.oa4mp.client.api.storage.AssetStore;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.exceptions.UnregisteredObjectException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.util.crypto.CertUtil;
import edu.uiuc.ncsa.security.util.crypto.KeyUtil;
import edu.uiuc.ncsa.security.util.crypto.MyPKCS10CertRequest;
import junit.framework.TestCase;
import org.junit.Test;

import java.net.URI;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.util.ArrayList;

/**
 * Basic testing of the asset store implementations.
 * <p>Created by Jeff Gaynor<br>
 * on 1/29/13 at  11:53 AM
 */
public class AssetStoreTest extends TestCase {


    @Test
    public void testAsset() throws Exception {
        Identifier id = BasicIdentifier.newID("asset:id:/" + ClientTestStoreUtil.getRandomString());
        Asset asset = new Asset(id);
        PrivateKey privateKey = KeyUtil.generateKeyPair().getPrivate();
        String username = "testUser-" + ClientTestStoreUtil.getRandomString(8);
        URI redirect = URI.create("http://test.foo/test" + ClientTestStoreUtil.getRandomString(8));
        asset.setPrivateKey(privateKey);
        asset.setUsername(username);
        asset.setRedirect(redirect);


        assert asset.getPrivateKey().equals(privateKey);
        assert asset.getUsername().equals(username);
        assert asset.getRedirect().equals(redirect);

    }

    public void testUpdate(AssetStore store) throws Exception {
        if (store == null) {
            System.out.println("WARNING: no asset store configured, skipping test.");
            return;
        }
        SecureRandom secureRandom = new SecureRandom();
        String r1 = Long.toHexString(secureRandom.nextLong());
        KeyPair kp1 = KeyUtil.generateKeyPair();
        PrivateKey privateKey1 = kp1.getPrivate();
        MyPKCS10CertRequest cr1 = CertUtil.createCertRequest(kp1);
        String rawCR1 = CertUtil.fromCertReqToString(cr1);
        String username1 = "testUser-" + r1;
        URI redirect1 = URI.create("http://test.foo/test/" + r1 +"/" +  System.currentTimeMillis());
        Identifier token1 = BasicIdentifier.newID("token:id:/" + r1 + "/" + System.currentTimeMillis());

        Identifier id1 = BasicIdentifier.newID("asset:id:/" + r1 + "/" + System.currentTimeMillis());
        Asset asset = store.create();
        assert asset != null : " The store is not producing valid assets when requested. A null was returned";
        asset.setIdentifier(id1);
        asset.setUsername(username1);
        asset.setPrivateKey(privateKey1);
        asset.setRedirect(redirect1);
        asset.setToken(token1);
        asset.setCertReq(cr1);

        store.save(asset);
        // Now try and update the identifier -- that should fail.
        String r2 = Long.toHexString(secureRandom.nextLong());
        Identifier id2 = BasicIdentifier.newID("asset:id:/" + r2 + "/"+ System.currentTimeMillis());
        asset.setIdentifier(id2);
        // Updating the identifier should fail as per the contract with the store, since an unknown
        // identifier means the object needs to be registered first.
        boolean bad = true;
        try {
            store.update(asset);
        } catch (UnregisteredObjectException t) {
            bad = false;
        }
        if(bad){
            assert false : " was able to update the identifier.";
        }

        // ok, set the id back since that worked.
        asset.setIdentifier(id1);
        // now for everything else.
        KeyPair kp2 = KeyUtil.generateKeyPair();
        PrivateKey privateKey2 = kp2.getPrivate();
        MyPKCS10CertRequest cr2 = CertUtil.createCertRequest(kp2);
        String rawCR2 = CertUtil.fromCertReqToString(cr2);
        String username2 = "testUser-" + r2;
        URI redirect2 = URI.create("http://test.foo/test/" + r2 + "/" +  System.currentTimeMillis());
        Identifier token2 = BasicIdentifier.newID("token:id:/" + r1 + "/" + System.currentTimeMillis());

        asset.setUsername(username2);
        asset.setPrivateKey(privateKey2);
        asset.setCertReq(cr2);
        asset.setRedirect(redirect2);
        asset.setToken(token2);
        store.update(asset);
        Asset asset2 = store.get(asset.getIdentifier());

        assert asset2.getUsername().equals(username2);
        assert asset2.getPrivateKey().equals(privateKey2);
        assert CertUtil.fromCertReqToString(asset2.getCertReq()).equals(rawCR2);
        assert asset2.getToken().equals(token2);
        assert asset2.getRedirect().equals(redirect2);
        store.remove(asset.getIdentifier());

    }


    /**
     * @param store
     * @return
     * @throws Exception
     */
    public void storeTest(AssetStore store) throws Exception {

        if (store == null) {
            System.out.println("WARNING: no asset store configured, skipping test.");
            return;
        }
        int count = 10;
        ArrayList<Asset> assets = new ArrayList<>();
        SecureRandom secureRandom = new SecureRandom();
        long l = secureRandom.nextLong();
        String r = Long.toHexString(l);
        KeyPair kp = KeyUtil.generateKeyPair();
        PrivateKey privateKey = kp.getPrivate();
        MyPKCS10CertRequest cr = CertUtil.createCertRequest(kp);
        String rawCR = CertUtil.fromCertReqToString(cr);

        for (int i = 0; i < count; i++) {
            Identifier id = BasicIdentifier.newID("asset:id:/" + r + "/" + i);
            Asset asset = store.create();
            assert asset != null : " The store is not producing valid assets when requested. A null was returned";
            assets.add(asset);
            asset.setIdentifier(id);
            String username = "testUser-" + r;
            URI redirect = URI.create("http://test.foo/test/" + r);

            asset.setPrivateKey(privateKey);
            asset.setUsername(username);
            asset.setRedirect(redirect);
            asset.setCertReq(cr);

            store.save(asset);

        }

        // now read it back.

        for (Asset asset : assets) {
            Asset asset2 = store.get(asset.getIdentifier());
            assert asset2 != null : "No asset found for identifier \"" + asset.getIdentifier() + "\" on iteration # ";
            assert asset.getIdentifier().equals(asset2.getIdentifier()) : "Identifiers on assets do not match. " +
                    "Expected \"" + asset.getIdentifierString() + "\" but got \"" + asset2.getIdentifierString() + "\"";
            assert asset.getUsername().equals(asset2.getUsername()) : "Username on assets do not match. " +
                    "Expected \"" + asset.getUsername() + "\" but got \"" + asset2.getUsername();
            assert asset.getPrivateKey().equals(asset2.getPrivateKey()) : "Private keys on assets do not match. " +
                    "Expected \"" + asset.getPrivateKey() + "\" but got \"" + asset2.getPrivateKey();
            assert asset.getRedirect().equals(asset2.getRedirect()) : "Redirect on assets do not match. " +
                    "Expected \"" + asset.getRedirect() + "\" but got \"" + asset2.getRedirect();
            // Special note: MySQL will truncate nanoseconds from dates so the best we can do is verify the milliseconds match.
            assert Math.abs(asset.getCreationTime().getTime() - asset2.getCreationTime().getTime()) < 1000 : "Timestamp on assets do not match. " +
                    "Expected \"" + asset.getCreationTime() + "\" but got \"" + asset2.getCreationTime() + "\"";
            // Generally there is no good concept of equality between certificatiion requests. In this specific case though,
            // the requests should be identical so we can compare them as strings. This is a data integrity test.
            assert rawCR.equals(CertUtil.fromCertReqToString(asset2.getCertReq())) : "Certification requests on assets do not match. " +
                    "Expected \"" + asset.getCertReq() + "\" but got \"" + asset2.getCertReq();
            // Don't clutter up the store with test cases.
            store.remove(asset.getIdentifier());

        }

    }

    @Test
    public void testMemoryStore() throws Exception {
        storeTest(ClientTestStoreUtil.getMemoryStore());
    }

    @Test
    public void testFileStore() throws Exception {
        storeTest(ClientTestStoreUtil.getFileStore());
    }


    @Test
    public void testPGStore() throws Exception {
        storeTest(ClientTestStoreUtil.getPostgresStore());
    }

    @Test
    public void testMySQLStore() throws Exception {
        storeTest(ClientTestStoreUtil.getMysqlStore());
    }

    @Test
    public void testUpdateMemoryStore() throws Exception {
        testUpdate(ClientTestStoreUtil.getMemoryStore());
    }

    @Test
    public void testUpdateFileStore() throws Exception {
        testUpdate(ClientTestStoreUtil.getFileStore());
    }


    @Test
    public void testUpdatePGStore() throws Exception {
        testUpdate(ClientTestStoreUtil.getPostgresStore());
    }

    @Test
    public void testUpdateMySQLStore() throws Exception {
        testUpdate(ClientTestStoreUtil.getMysqlStore());
    }
}
