package edu.uiuc.ncsa.oa4mp.delegation.common.storage;

import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.exceptions.GeneralException;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.IdentifiableProviderImpl;
import edu.uiuc.ncsa.security.core.util.IdentifierProvider;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.BasicTransaction;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.BasicTransactionConverter;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.BasicTransactionProvider;
import edu.uiuc.ncsa.oa4mp.delegation.common.storage.transactions.FSTransactionStore;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AccessToken;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.AuthorizationGrant;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.TokenForge;
import edu.uiuc.ncsa.oa4mp.delegation.common.token.Verifier;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import javax.servlet.http.HttpServletRequest;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.List;
import java.util.Map;

/**
 * <p>Created by Jeff Gaynor<br>
 * on Apr 28, 2010 at  3:33:34 PM
 */
public class FileStoreTest extends BaseTransactionStoreTest {
    protected static class TestTokenForge implements TokenForge {

        @Override
        public AccessToken getAccessToken(Map<String, String> parameters) {
            return null;
        }

        @Override
        public AuthorizationGrant getAuthorizationGrant(Map<String, String> parameters) {
            return null;
        }

        @Override
        public AuthorizationGrant getAuthorizationGrant(HttpServletRequest request) {
            return null;
        }

        @Override
        public AuthorizationGrant getAuthorizationGrant(String... tokens) {
            if(tokens.length == 0 ){
                return new FakeAuthorizationGrant((String) null);
            }
            return new FakeAuthorizationGrant(tokens[0]);
        }

        @Override
        public AccessToken getAccessToken(HttpServletRequest request) {
            return null;
        }

        @Override
        public AccessToken getAccessToken(String... tokens) {
            if(tokens.length == 0 ) {
                return new FakeAccessToken((String) null);
            }
            return new FakeAccessToken(tokens[0]);

        }

        @Override
        public Verifier getVerifier(Map<String, String> parameters) {
            return null;
        }

        @Override
        public Verifier getVerifier(HttpServletRequest request) {
            return null;
        }

        @Override
        public Verifier getVerifier(String... tokens) {
            if(tokens.length == 0 ) {
                return new FakeVerifier((String) null);
            }
            return new FakeVerifier(tokens[0]);
        }
    }

    @Override
    protected AuthorizationGrant newAG(URI id) {
        return new FakeAuthorizationGrant(id.toString());
    }

    @Override
    protected Verifier newVerifier(URI id) {
        return new FakeVerifier(id.toString());
    }

    @Override
    protected AccessToken newAT(URI id) {
        return new FakeAccessToken(id.toString());
    }

    public static File getTempDir() {
        File tempDir = new File(System.getProperty("java.io.tmpdir")); // system-wide location for temp files
        File testDir = null;
        try {
            testDir = File.createTempFile("ncsa-test", "", tempDir);
        } catch (IOException e) {
            throw new GeneralException("Could not create testing directory \"" + testDir + "\"");
        }
        testDir.delete();
        testDir.mkdirs();

        return testDir;
    }

    static TransactionStore fileStore = null;
    // since we need this to preserve state, we make a static instance of the store and manage that.

    public TransactionStore<BasicTransaction> getStore() throws IOException {
        if (fileStore == null) {
            TestTokenForge ttf = new TestTokenForge();
            IdentifierProvider<Identifier> idp = new IdentifierProvider<Identifier>("transactions") {};
            IdentifiableProviderImpl<BasicTransaction> btp = new BasicTransactionProvider<BasicTransaction>(idp);
            fileStore = new TestFileStore(getTempDir(), btp, ttf);
        }
        return fileStore;
    }


    public static class TestFileStore extends FSTransactionStore<BasicTransaction> {
        @Override
        public List<BasicTransaction> getMostRecent(int n, List<String> attributes) {
            return null;
        }

        @Override
        public BasicTransaction getByProxyID(Identifier proxyID) {
            throw new NotImplementedException("Error: This is not yet implemented for cache");
        }

        @Override
        public XMLConverter getXMLConverter() {
            throw new NotImplementedException("Error: Method not implemented");
        }
        public TestFileStore(File file, IdentifiableProviderImpl<BasicTransaction> btp, TestTokenForge ttf) throws IOException {
            super(new File(file, "data"), new File(file, "index"), btp, ttf, new BasicTransactionConverter(btp, ttf), true);

    };

        @Override
        public MapConverter getMapConverter() {
            throw new NotImplementedException("Error:  Method not implemented");
        }

        @Override
    public BasicTransaction create() {
        return new BasicTransaction((Identifier) null);
    }
}

    /**
     * <p>Created by Jeff Gaynor<br>
     * on May 6, 2011 at  3:19:07 PM
     */
    public static class FakeVerifier extends FakeTokenImpl implements Verifier {
        public FakeVerifier(String token) {
            super(token);
        }

        public FakeVerifier(URI token) {
            super(token);
        }

    }

    /**
     * <p>Created by Jeff Gaynor<br>
     * on May 6, 2011 at  3:19:29 PM
     */
    public static class FakeAuthorizationGrant extends FakeTokenImpl implements AuthorizationGrant {
        public FakeAuthorizationGrant(String token) {
            super(token);
        }

        public FakeAuthorizationGrant(URI token) {
            super(token);
        }

        @Override
        public boolean equals(Object obj) {
            if (!super.equals(obj)) return false;
            if (!(obj instanceof AuthorizationGrant)) return false;
            return true;

        }
    }

    /**
     * <p>Created by Jeff Gaynor<br>
     * on May 6, 2011 at  3:19:16 PM
     */
    public static class FakeAccessToken extends FakeTokenImpl implements AccessToken {


        public FakeAccessToken(String token) {
            super(token);
        }

        public FakeAccessToken(URI token) {
            super(token);
        }

        @Override
        public boolean equals(Object obj) {
            if (!super.equals(obj)) return false;
            if (!(obj instanceof AccessToken)) return false;
            return true;
        }
    }
}
