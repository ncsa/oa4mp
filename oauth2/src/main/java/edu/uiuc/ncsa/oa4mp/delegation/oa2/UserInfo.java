package edu.uiuc.ncsa.oa4mp.delegation.oa2;

import edu.uiuc.ncsa.security.core.util.DebugUtil;
import net.sf.json.JSONObject;

import java.util.HashMap;
import java.util.Map;

import static edu.uiuc.ncsa.oa4mp.delegation.oa2.server.claims.OA2Claims.*;

/**
 * This class manages information related to the UserInfo OIDC query.
 * The only required field is "sub" -- all others are optional.  The
 * getJSON() method should return a JSON response string based on the
 * class variables.  Can be subclassed to support getting user info
 * from different sources. This uses a map internally
 * since otherwise it is much trickier to
 * turn this into a valid JSON object.
 */

public class UserInfo {
    Map<String, Object> map;

    public Map<String, Object> getMap() {
        if (map == null) {
            map = new HashMap<>();
        }
        return map;
    }

    public void setMap(Map<String, Object> map) {
        this.map = map;
    }

    public JSONObject toJSon(){
        if(map == null ) return null;
        DebugUtil.trace(this, "map is " + map);

        if(map instanceof JSONObject){
            return (JSONObject) map;
        }
        JSONObject jj = JSONObject.fromObject(map);
        DebugUtil.trace(this, "JSON object from map is " + jj);
        return jj;
    }
    public String getString(String key) {
        Object x = getMap().get(key);
        if (x == null) return null;
        return x.toString();
    }

    public boolean getBoolean(String key) {
        Object x = getMap().get(key);
        if (x instanceof Boolean) return (Boolean) x;
        return false;
    }

    public int getInt(String key) {
        Object x = getMap().get(key);
        if (x instanceof Integer) return (Integer) x;
        return 0;
    }

    public JSONObject getJSON(String key){
        return (JSONObject)getMap().get(key);
    }
    public void put(String key, String value) {
        getMap().put(key, value);
    }

    public void put(String key, Boolean x){
                    getMap().put(key,x);
    }
    public void put(String key, Integer x){
        getMap().put(key,x);
    }
    public void put(String key, JSONObject json){
        getMap().put(key,json);
    }
    public UserInfo() {
    }

    public String getSub() {
        return getString(SUBJECT);
    }

    public void setSub(String sub) {
        put(SUBJECT, sub);
    }

    public String getName() {
        return getString(NAME);
    }

    public void setName(String name) {
        put(NAME, name);
    }

    public String getGiven_name() {
        return getString(GIVEN_NAME);
    }

    public void setGiven_name(String given_name) {
        put(GIVEN_NAME, given_name);
    }

    public String getFamily_name() {
        return getString(FAMILY_NAME);
    }

    public void setFamily_name(String family_name) {
        put(FAMILY_NAME, family_name);
    }

    public String getMiddle_name() {
        return getString(MIDDLE_NAME);
    }

    public void setMiddle_name(String middle_name) {
        put(MIDDLE_NAME, middle_name);
    }

    public String getNickname() {
        return getString(NICKNAME);
    }

    public void setNickname(String nickname) {
        put(NICKNAME, nickname);
    }

    public String getPreferred_username() {
        return getString(PREFERRED_USERNAME);
    }

    public void setPreferred_username(String preferred_username) {
        put(PREFERRED_USERNAME, preferred_username);
    }

    public String getPicture() {
        return getString(PICTURE);
    }

    public void setPicture(String picture) {
        put(PICTURE, picture);
    }

    public String getWebsite() {
        return getString(WEBSITE);
    }

    public void setWebsite(String website) {
        put(WEBSITE, website);
    }

    public String getEmail() {
        return getString(EMAIL);
    }

    public void setEmail(String email) {
        put(EMAIL, email);
    }

    public boolean isEmail_verified() {
        return getBoolean(EMAIL_VERIFIED);
    }

    public void setEmail_verified(boolean email_verified) {
        put(EMAIL_VERIFIED, email_verified);
    }
    public String getGender() {
        return getString(GENDER);
    }

    public void setGender(String gender) {
        put(GENDER, gender);
    }

    public String getBirthdate() {
        return getString(BIRTHDATE);
    }

    public void setBirthdate(String birthdate) {
        put(BIRTHDATE, birthdate);
    }

    public String getZoneinfo() {
        return getString(ZONEINFO);
    }

    public void setZoneinfo(String zoneinfo) {
        put(ZONEINFO, zoneinfo);
    }

    public String getLocale() {
        return getString(LOCALE);
    }

    public void setLocale(String locale) {
        put(LOCALE, locale);
    }

    public String getPhone_number() {
        return getString(PHONE_NUMBER);
    }

    public void setPhone_number(String phone_number) {
        put(PHONE_NUMBER, phone_number);
    }

    public boolean isPhone_number_verified() {
        return getBoolean(PHONE_NUMBER_VERIFIED);
    }

    public void setPhone_number_verified(boolean phone_number_verified) {
        put(PHONE_NUMBER_VERIFIED, phone_number_verified);
    }

    public JSONObject getAddress() {
        return getJSON(ADDRESS);
    }

    public void setAddress(JSONObject address) {
        put(ADDRESS, address);
    }

    public int getUpdated_at() {return getInt(UPDATED_AT);}
    public void setUpdated_at(int updated_at) {put(UPDATED_AT,updated_at);}
}
