package org.oa4mp.server.admin.oauth2.tools;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.exceptions.NotImplementedException;
import edu.uiuc.ncsa.security.core.util.AbstractEnvironment;
import edu.uiuc.ncsa.security.core.util.ConfigurationLoader;
import edu.uiuc.ncsa.security.util.cli.CLIDriver;
import edu.uiuc.ncsa.security.util.cli.ConfigurableCommandsImpl2;
import edu.uiuc.ncsa.security.util.cli.InputLine;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKey;
import edu.uiuc.ncsa.security.util.jwk.JSONWebKeys;
import net.sf.json.JSONArray;
import org.oa4mp.server.api.admin.adminClient.AdminClient;
import org.oa4mp.server.api.admin.adminClient.AdminClientStore;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/*
   This extends {@link ConfigurableCommandsImpl2} to provide a command line interface for managing keys.
   It is not (at this point) intended to be used as a standalone command line utility,
   hence most of the bootstrapping machinery is not implemented.
 */
public class KeyCommands extends ConfigurableCommandsImpl2 {
    @Override
    public String getComponentName() {
        throw new NotImplementedException("Not implemented.");
    }

    @Override
    public ConfigurationLoader<? extends AbstractEnvironment> getLoader() {
        throw new NotImplementedException("Not implemented.");
    }

    @Override
    public void setLoader(ConfigurationLoader<? extends AbstractEnvironment> loader) {
        throw new NotImplementedException("Not implemented.");
    }

    @Override
    protected ConfigurationLoader<? extends AbstractEnvironment> figureOutLoader(String fileName, String configName) throws Throwable {
        throw new NotImplementedException("Not implemented.");
    }

    @Override
    public void useHelp() {

    }

    @Override
    public void about(boolean showBanner, boolean showHeader) {

    }

    @Override
    public String getPrompt() {
        return "jwks>";
    }

    public KeyCommands(CLIDriver driver, AdminClientStore store, AdminClient adminClient) throws Throwable {
        super(driver);
        this.adminClient = adminClient;
        this.adminClientStore = store;
        init();
    }

    public AdminClientStore getAdminClientStore() {
        return adminClientStore;
    }

    public void setAdminClientStore(AdminClientStore adminClientStore) {
        this.adminClientStore = adminClientStore;
    }

    AdminClientStore adminClientStore;
    public AdminClient getAdminClient() {
        return adminClient;
    }

    public void setAdminClient(AdminClient adminClient) {
        this.adminClient = adminClient;
    }

    AdminClient adminClient;

    public JSONWebKeys getWebKeys() {
        return webKeys;
    }

    public void setWebKeys(JSONWebKeys webKeys) {
        this.webKeys = webKeys;
    }

    JSONWebKeys webKeys;

    protected void init() throws Throwable {
        webKeys = adminClient.getJWKS();
    }



    public void add(InputLine inputLine) throws Throwable {
    }

    /**
     * Expire a key or list of them by ID.
     * @param inputLine
     * @throws Throwable
     */
    public void expire(InputLine inputLine) throws Throwable {
    }

    public JSONArray expire(JSONArray list, long expirationDate) throws Throwable {
        List<Long> exp = new ArrayList<>(1);
        exp.add(expirationDate);
        return expire(list, exp);
    }

    /**
     * Takes a list of key ids and a list of expiration dates and expires them.
     * If the list is a singleton, the same expiration date is used for all keys.
     * @param list
     * @param expirationDates
     * @return A list of keys that were not found.
     * @throws IllegalArgumentException if the lists are not the same size.
     */
    public JSONArray expire(JSONArray list, List<Long> expirationDates)  {
        boolean isSingleton = expirationDates.size() == 1;
        if(!isSingleton){
            if(expirationDates.size() != list.size()){
                throw new IllegalArgumentException("Length mismatch error: Expiration dates must be the same size as the list of keys ids.");
            }
        }
        JSONArray skipped = new JSONArray();
        for(int i=0; i<list.size(); i++){
            Object o = list.get(i);
            if(o instanceof String){
                String currentID = (String)o;
                if(getWebKeys().containsKey(currentID)){
                    JSONWebKey currentKey = getWebKeys().get(currentID);
                    long currentExp;
                    if(isSingleton){
                        currentExp = expirationDates.get(0);
                    }else{
                        currentExp = expirationDates.get(i);
                    }
                    currentKey.expiresAt = new Date(currentExp);
                }else{
                    skipped.add(o);
                }
            }else{
                skipped.add(o);
            }
        } // end for
        getAdminClient().setJWKS(getWebKeys());
        getAdminClientStore().save(getAdminClient());
        return skipped;

    }

    public void rm(InputLine inputLine) throws Throwable {
    }

    /**
     * Removes keys either using the IDs (if any are found) or by expiration date.
     * Returns any keys that requested were not processed (usually because they were not found).
     * @param ids
     * @param expirationDates
     * @throws Throwable
     */
    public JSONArray rm(JSONArray ids, List<Long> expirationDates) throws Throwable {
       JSONArray skipped = new JSONArray();
       boolean gotOne = false;
       skipped.addAll(ids); // copy to avoid concurrent modification error
        for(JSONWebKey jwk : getWebKeys().values()){
            if(expirationDates.contains(jwk.expiresAt.getTime())){
                getWebKeys().remove(jwk.id);
                gotOne = true;
            }else{
                if(ids.contains(jwk.id)){
                    getWebKeys().remove(jwk.id);
                    skipped.remove(jwk.id);
                    gotOne = true;
                }
            }
        } // end for
        if(gotOne){
            getAdminClient().setJWKS(getWebKeys());
            getAdminClientStore().save(getAdminClient());
        }
        return skipped;
    }

    public void archive(InputLine inputLine) throws Throwable {

    }

    public void save(InputLine inputLine) throws Throwable {
    }

    public void read(InputLine inputLine) throws Throwable {
    }

    protected String format(Identifiable identifiable) {
        return "";
    }

    @Override
    public String getName() {
        return "jwks";
    }
}
