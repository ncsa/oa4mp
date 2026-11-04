package org.oa4mp.server.jetty;

import edu.uiuc.ncsa.security.core.cf.CFBundle;
import edu.uiuc.ncsa.security.core.cf.CFLoader;
import edu.uiuc.ncsa.security.core.cf.CFNode;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import org.eclipse.jetty.ee11.servlet.ServletContextHandler;
import org.eclipse.jetty.server.*;
import org.eclipse.jetty.util.resource.Resource;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.ee11.webapp.WebAppContext;
import org.oa4mp.server.api.ServiceEnvironmentImpl;
import org.oa4mp.server.api.storage.servlet.OA4MPServlet;
import org.oa4mp.server.loader.oauth2.OA2SE;
import org.oa4mp.server.loader.oauth2.loader.OA2CFConfigurationLoader;
import org.oa4mp.server.loader.oauth2.loader.OA2ServletInitializer;
import org.qdl_lang.parsing.IniParserDriver;
import org.qdl_lang.variables.QDLStem;

import java.io.File;
import java.io.FileInputStream;
import java.io.StringReader;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Main Jetty server class. This allows OA4MP to be run as a standalone server.
 */
public class JettyServer {
    public static void main(String[] args) throws Throwable {
        System.setProperty("org.eclipse.jetty.LEVEL", "DEBUG");

        JettyServer jettyServer = new JettyServer();
        //httpSetup();
        //jettyServer.httpsSetup();
        jettyServer.oa4mpStart();
    }

    protected void httpsSetup() throws Throwable {
        // 1. Create the main server instance
        Server server = new Server(8443);

        // 2. HTTP Configuration for secure requests
        HttpConfiguration httpsConfig = new HttpConfiguration();
        // SecureRequestCustomizer appends SSL/TLS parameters to the request object
        httpsConfig.addCustomizer(new SecureRequestCustomizer());

        // 3. Configure the SSL Context Factory with your Keystore
        // Note: For Jetty 10+, use SslContextFactory.Server() instead of the base class
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        QDLStem ini = getIni();
        QDLStem ssl = ini.getStem("ssl");
        sslContextFactory.setKeyStorePath(ssl.getString("keystore_path"));
        sslContextFactory.setKeyStorePassword(ssl.getString("keystore_password"));
        sslContextFactory.setKeyManagerPassword(ssl.getString("keystore_manager_password"));

        // 4. Create the HTTPS Server Connector
        // It couples the SSL factory (handling encryption) with the HTTP factory (handling logic)
        ServerConnector httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, "http/1.1"),
                new HttpConnectionFactory(httpsConfig));

        httpsConnector.setPort(8443); // Your custom HTTPS port

        // 5. Bind the connector to the server
        server.setConnectors(new Connector[]{httpsConnector});

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);
        // 3. Link your Servlet to a specific URL path mapping
        context.addServlet(HelloServlet.class, "/hello");

        System.out.println("Starting embedded secure Jetty server on port 8443...");

        server.start();
        server.join();
    }

    protected void httpSetup() throws Exception {
        Server server = new Server(8080);

        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);
        // 3. Link your Servlet to a specific URL path mapping
        context.addServlet(HelloServlet.class, "/hello");

        // 4. Start the server engine
        System.out.println("Starting embedded Jetty server on port 8080...");
        server.start();

        // 5. Join the current thread to block until the server shuts down
        server.join();
    }

    /**
     * Reads the OA4MP ini file. The file contains the information for bootstrapping
     * the server (such as keys, where the OA4MP configuration file is located, etc)
     * and not OA4MP.
     *
     * @return
     * @throws Throwable
     */
    protected QDLStem getIni() throws Throwable {
        IniParserDriver iniParserDriver = new IniParserDriver();
        String content = Files.readString(java.nio.file.Paths.get("/home/ncsa/dev/csd/config/jetty.ini"));
        StringReader stringReader = new StringReader(content);
        QDLStem out = iniParserDriver.parse(stringReader, false);
        System.out.println(out);
        return out;
    }


    protected OA2CFConfigurationLoader<? extends ServiceEnvironmentImpl> getLoader(CFNode cfNode) {
        OA2CFConfigurationLoader<? extends ServiceEnvironmentImpl> loader = new OA2CFConfigurationLoader<>(cfNode);
        return loader;
    }

    /**
     * Sets up OA4MP from the configuration file. Att eh end of this call, the
     * configuration file has been read, the initializer created and the environment
     * has beenb created.
     *
     * @param cfg The OA4MP specific configuration.
     * @throws Throwable
     */
    protected void oa4mpBootstrap(QDLStem cfg) throws Throwable {
        CFLoader cfLoader = new CFLoader();
        File cfgFile = new File(cfg.getString("cfg"));
        System.out.println("Loading configuration from " + cfgFile.getAbsolutePath());
        FileInputStream in = new FileInputStream(cfgFile);
        CFBundle bundle = cfLoader.loadBundle(in, "service");
        CFNode cfNode = bundle.getNamedConfig(cfg.getString("name"));
        OA4MPServlet.setInitialization(new OA2ServletInitializer());

        OA2SE oa2SE = (OA2SE) getLoader(cfNode).createInstance();
        OA4MPServlet.setEnvironment(oa2SE);
    }

    /**
     * Starts OA4MP proper. This assumes that {@link #oa4mpBootstrap(QDLStem)} has been called
     * and the environment has been created.
     *
     * @throws Throwable
     */
    protected void oa4mpStart() throws Throwable {
        HttpConfiguration httpsConfig = new HttpConfiguration();
        // SecureRequestCustomizer appends SSL/TLS parameters to the request object
        httpsConfig.addCustomizer(new SecureRequestCustomizer());

        // 3. Configure the SSL Context Factory with your Keystore
        // Note: For Jetty 10+, use SslContextFactory.Server() instead of the base class
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        QDLStem ini = getIni();
        QDLStem ssl = ini.getStem("ssl");
        QDLStem oa4mp = ini.getStem("oa4mp");
        sslContextFactory.setKeyStorePath(ssl.getString("keystore_path"));
        sslContextFactory.setKeyStorePassword(ssl.getString("keystore_password"));
        sslContextFactory.setKeyManagerPassword(ssl.getString("keystore_manager_password"));
        oa4mpBootstrap(oa4mp);

        Server server = new Server(oa4mp.getLong("port").intValue());

        ServerConnector httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory, "http/1.1"),
                new HttpConnectionFactory(httpsConfig));

        httpsConnector.setPort(oa4mp.getLong("port").intValue()); // Your custom HTTPS port

        // 5. Bind the connector to the server
        server.setConnectors(new Connector[]{httpsConnector});

        WebAppContext context = new WebAppContext(oa4mp.getString("war"),oa4mp.getString("path"));
context.setLogUrlOnStart(true);
        // 3. Set the context path (e.g., "/" for root)
   //     context.setContextPath(oa4mp.getString("path"));

        // 4. Point explicitly to your web.xml deployment descriptor
        //context.setDescriptor("src/main/webapp/WEB-INF/web.xml");
        //    context.setDescriptor(oa4mp.getString("descriptor"));
   //     context.setWar(oa4mp.getString("war"));

        context.setDisplayName("OA4MP");
        //context.setBaseResource(new FileResource(new File("src/main/webapp")));
        // context.setBaseResource(new FileResource(new File(oa4mp.getString("base"))));

        // 6. Ensure the webapp classloader parent priority behaves as expected (optional)
        context.setParentLoaderPriority(true);

        // 7. Attach the context handler to the server and start
        server.setHandler(context);
        server.start();
        server.join();
    }

    public static class FileResource extends Resource {
        FileResource(File file) {
            this.file = file;
        }

        @Override
        public Path getPath() {
            return file.toPath();
        }

        @Override
        public boolean isDirectory() {
            return file.isDirectory();
        }

        @Override
        public boolean isReadable() {
            return file.canRead();
        }

        @Override
        public URI getURI() {
            return file.toURI();
        }

        @Override
        public String getName() {
            return file.getName();
        }

        @Override
        public String getFileName() {
            return file.getAbsolutePath();
        }

        @Override
        public Resource resolve(String subUriPath) {
            throw new NotImplementedException("resolve not implemented");
        }

        private final File file;
    }
}
