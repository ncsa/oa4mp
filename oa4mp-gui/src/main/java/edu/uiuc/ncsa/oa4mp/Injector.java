package edu.uiuc.ncsa.oa4mp;


import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2Client;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientConverter;
import edu.uiuc.ncsa.myproxy.oa4mp.oauth2.storage.clients.OA2ClientProvider;
import edu.uiuc.ncsa.myproxy.oa4mp.server.admin.transactions.OA4MPIdentifierProvider;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Constants;
import edu.uiuc.ncsa.security.oauth_2_0.OA2Scopes;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.claims.ClaimSourceConfigurationUtil;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfiguration;
import edu.uiuc.ncsa.security.oauth_2_0.server.config.LDAPConfigurationUtil;
import edu.uiuc.ncsa.security.storage.XMLMap;
import net.sf.json.JSONArray;
import net.sf.json.JSONObject;

import java.io.FileInputStream;
import java.util.Collection;

import static edu.uiuc.ncsa.myproxy.oa4mp.oauth2.state.OA2ClientFunctorScriptsUtil.*;
import static edu.uiuc.ncsa.security.oauth_2_0.server.scripts.ClientJSONConfigUtil.getComment;

/**
 * This will read a client configuration and inject it in to the UI.
 *
 * <p>Created by Jeff Gaynor<br>
 * on 12/20/19 at  2:01 PM
 */
public class Injector {
    Controller controller = null;

    public Injector(Controller controller) {
        this.controller = controller;
    }

    OA2Client client = null;

    public OA2Client readRecord(String file) throws Exception {
        FileInputStream fis = new FileInputStream(file);
        XMLMap xmlMap = new XMLMap();
        xmlMap.fromXML(fis);
        fis.close();
        OA2ClientProvider clientProvider = new OA2ClientProvider(new OA4MPIdentifierProvider(OA2Constants.CLIENT_ID, false));

        OA2ClientConverter clientConverter = new OA2ClientConverter(clientProvider);
        client = (OA2Client) clientConverter.fromMap(xmlMap);
        return client;
    }

    protected void inject() {
        controller.cb_isPublic.setSelected(client.isPublicClient());
        controller.field_name.setText(client.getName());
        controller.field_email.setText(client.getEmail());
        controller.field_id.setText(client.getIdentifierString());
        controller.field_secret.setText(client.getSecret());
        controller.field_home_uri.setText(client.getHomeUri());
        if (client.isRTLifetimeEnabled()) {
            controller.field_refresh_lifetime.setText(Long.toString(client.getRtLifetime()));
        }
        Collection<String> callbackURIs = client.getCallbackURIs();
        StringBuilder stringBuilder = new StringBuilder();
        for (String x : callbackURIs) {
            stringBuilder.append(x + "\n");
        }
        controller.field_redirect.setText(stringBuilder.toString());
        Collection<String> scopes = client.getScopes();
        controller.cb_open_id.setSelected(scopes.contains(OA2Scopes.SCOPE_OPENID));
        controller.cb_email.setSelected(scopes.contains(OA2Scopes.SCOPE_EMAIL));
        controller.cb_profile.setSelected(scopes.contains(OA2Scopes.SCOPE_PROFILE));
        controller.cb_user_info.setSelected(scopes.contains(OA2Scopes.SCOPE_CILOGON_INFO));
        controller.cb_get_cert.setSelected(scopes.contains(OA2Scopes.SCOPE_MYPROXY));
        JSONObject cfg = client.getConfig();
        JSONArray comments = getComment(cfg);
        stringBuilder = new StringBuilder(); // re-use it
        for(Object y : comments){
            stringBuilder.append(y.toString() + "\n");
        }
        controller.text_comments.setText(stringBuilder.toString());
        if(hasClaimPreProcessor(cfg)) {
            controller.ta_global_preProcessor.setText(getClaimsPreProcessing(cfg).toString(2));
        }
        if(hasClaimSources(cfg)){
            System.out.println("has claims sources " + getClaimSources(cfg).toString(2));

        }else{
            System.out.println("has NO claims sources." );
        }
        if(hasClaimSourceConfigurations(cfg)){
            JSONArray claimsSources = getClaimSourceConfigurations(cfg);
            System.out.println("has claims source configurations " + claimsSources.toString(2));
            LDAPConfigurationUtil ld = new LDAPConfigurationUtil();
            if(ld.isLDAPCOnfig(claimsSources.getJSONObject(0))){
                LDAPConfiguration ldapConfiguration = ld.fromJSON(claimsSources.getJSONObject(0));
                controller.test_claim_source_name_1.setText(ldapConfiguration.getName());
                controller.test_claim_source_id_1.setText(ldapConfiguration.getId());
                /*
                yourTable.setModel(
                        new DefaultTableModel(data2, new String [] {"Column1Title", "Cloumn2Title"}) {
                        Class[] types = new Class[] {String.class,String.class};
                        boolean[] canEdit = new boolean[] {true, true};
                        @Override
                        public Class getColumnClass(int columnIndex){ return types [columnIndex];}
                        @Override
                        public boolean isCellEditable(int rowIndex, int columnIndex){ return canEdit [columnIndex];}
                });
                 */
            }else {
                ClaimSourceConfigurationUtil cscu = new ClaimSourceConfigurationUtil();
                ClaimSourceConfiguration cs = new ClaimSourceConfiguration();
                cscu.fromJSON(cs, claimsSources.getJSONObject(0));
            }

        }    else{
            System.out.println("has NO claims source  configurations.");

        }
    }

}
