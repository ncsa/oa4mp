package edu.uiuc.ncsa.myproxy.oa4mp.server;

import edu.uiuc.ncsa.security.core.Identifiable;
import edu.uiuc.ncsa.security.core.Identifier;
import edu.uiuc.ncsa.security.core.Store;
import edu.uiuc.ncsa.security.core.XMLConverter;
import edu.uiuc.ncsa.security.core.exceptions.NFWException;
import edu.uiuc.ncsa.security.core.util.BasicIdentifier;
import edu.uiuc.ncsa.security.core.util.DoubleHashMap;
import edu.uiuc.ncsa.security.core.util.StringUtils;
import edu.uiuc.ncsa.security.storage.XMLMap;
import edu.uiuc.ncsa.security.storage.data.MapConverter;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;

/**
 * Class to encapsulate archive CRUD operations for a store. Having it here lets
 * us use it in other places, e.g. QDL.
 * <p>Created by Jeff Gaynor<br>
 * on 10/19/21 at  6:14 AM
 */
public class StoreArchiver {
    public StoreArchiver(Store store) {
        this.store = store;
    }

    public Store getStore() {
        return store;
    }

    public MapConverter getMapConverter() {
        if (mapConverter == null) {
            XMLConverter xmlConverter = getStore().getXMLConverter();
            if (!(xmlConverter instanceof MapConverter)) {
                throw new NFWException("internal error: The XML converter for the store is not a MapConverter.");
            }
            mapConverter = (MapConverter) xmlConverter;
        }
        return mapConverter;
    }

    MapConverter mapConverter;
    Store store;
    /**
     * Key in the fragment for the version
     */
    static public String ARCHIVE_VERSION_TAG = "version";
    /**
     * Separator between the version tag and the version number.
     */
    static public String ARCHIVE_VERSION_SEPARATOR_TAG = "=";

    /**
     * Given a version id (of form URI#version=number), return the number.
     *
     * @param id
     * @return
     */
    public long getVersionNumber(Identifier id) {
        URI uri = id.getUri();
        String fragment = uri.getFragment();
        if (StringUtils.isTrivial(fragment)) {
            return -1L;
        }
        try {
            return Long.parseLong(fragment.substring(fragment.indexOf(ARCHIVE_VERSION_SEPARATOR_TAG) + 1));
        } catch (NumberFormatException nfx) {
            return -1L;
        }
    }

    /**
     * Given a base id and the new version number, create the identifier
     * <pre>
     *     URI#version=number
     * </pre>
     * This is to make sure everythign is created identically.
     *
     * @param id
     * @param version
     * @return
     */
    public Identifier createVersionedID(Identifier id, long version) {
        URI uri = id.getUri();
        String s = uri.getFragment();
        if (s != null && s.contains(ARCHIVE_VERSION_TAG + ARCHIVE_VERSION_SEPARATOR_TAG)) {
            throw new IllegalArgumentException(id + " already is versioned");
        }
        if (StringUtils.isTrivial(s)) {
            s = ARCHIVE_VERSION_TAG + ARCHIVE_VERSION_SEPARATOR_TAG + Long.toString(version);
        } else {
            s = s + "&" + ARCHIVE_VERSION_TAG + ARCHIVE_VERSION_SEPARATOR_TAG + Long.toString(version);
        }
        try {
            uri = new URI(uri.getScheme(), uri.getSchemeSpecificPart(), s);
        } catch (URISyntaxException uriSyntaxException) {
            throw new IllegalArgumentException("could not create uri for identifier:" + uriSyntaxException.getMessage());
        }

        return BasicIdentifier.newID(uri);
    }

    public static void main(String[] args) {
        StoreArchiver storeArchiver = new StoreArchiver(null);
        Identifier id = storeArchiver.createVersionedID(new BasicIdentifier("uri:test/foo"), 1L);
        System.out.println(id);
        System.out.println(storeArchiver.createVersionedID(new BasicIdentifier("uri:test/foo?boo=woof#fragment=foo"), 2L));
        System.out.println(storeArchiver.getVersionNumber(new BasicIdentifier("uri:new")));
        System.out.println(storeArchiver.getVersionNumber(id));
        ;
    }

    /**
     * For a given object in the store, return all the versions associated with it in a
     * {@link DoubleHashMap}.
     * Note that the keys are of the form
     * <pre>
     *     URI#version=number
     * </pre>
     * and the value is the number. As a double hash map then you can do a reverse lookup
     * by version number and get the unique identifier.
     *
     * @param identifier
     * @return
     */
    protected DoubleHashMap<URI, Long> getVersions(Identifier identifier) {
        MapConverter mc = getMapConverter();
        //  identifierString = escapeRegex(identifierString);
        List<Identifiable> values = getStore().search
                (mc.getKeys().identifier(),
                        identifier.toString() + ".*",
                        true);

        // now we have to look through the list of clients and determine which is the one we want
        DoubleHashMap<URI, Long> versionNumbers = new DoubleHashMap<>();
        for (Identifiable value : values) {
            URI uri = value.getIdentifier().getUri();
            String fragment = uri.getFragment();
            if (!StringUtils.isTrivial(fragment)) {
                // This does two things. First, it will no show the base version as archived
                // and secondly, will only add those with a valid versioning fragment
                String rawIndex = fragment.substring(1 + fragment.indexOf(ARCHIVE_VERSION_SEPARATOR_TAG));

                try {
                    if (!StringUtils.isTrivial(rawIndex)) {
                        versionNumbers.put(uri, Long.parseLong(rawIndex));
                    }
                } catch (Throwable t) {

                }
            }

        }
        return versionNumbers;
    }

    /**
     * For a given object, get all the versions (not just their identifiers) and
     * return in a map keyed by version number.  This sorts the entries.
     * Rather similar to {@link #getVersions(Identifier)}, this has key = number
     * and value =URI#version=number. Use this where you need all the versions
     * sorted by number for, e.g., display purposes.
     *
     * @param identifiable
     * @return
     */
    public TreeMap<Long, Identifiable> getVersionsMap(Identifiable identifiable) {
        MapConverter mc = getMapConverter();

        if (identifiable == null) {
            return null;
        }
        // Grab each client and run through information about them
        List<Identifiable> values = getStore().search
                (mc.getKeys().identifier(),
                        identifiable.getIdentifierString() + ".*",
                        true);

        TreeMap<Long, Identifiable> sortedMap = new TreeMap<>();
        // There is every reason to assume that there will be gaps ion the number sequences over time.
        // create a new set of these and manage the order manually.

        for (Identifiable x : values) {
            long version = getVersionNumber(x.getIdentifier());
            if (-1 < version) {
                sortedMap.put(version, x);
            }
        }

        // Now we run through them all in order
        return sortedMap;
    }

    /**
     * Get the latest version number or return a -1 if no versions present.
     * Remember that versions increase, so version 0 is the first made, 1 is the
     * next,... and the highest number is the most recent version.
     *
     * @param versionNumbers
     * @return
     */
    protected Long getLatestVersionNumber(DoubleHashMap<URI, Long> versionNumbers) {
        if (versionNumbers.isEmpty()) {
            return -1L;
        }
        long maxValue = 0L;
        for (URI key : versionNumbers.keySet()) {
            maxValue = Math.max(maxValue, versionNumbers.get(key));
        }
        return maxValue;
    }

    /**
     * Given the raw id and a version number (which may be -1 to indicate using the latest)
     * get the stored version. Might return null of there is no such version.
     *
     * @param targetID
     * @param version
     * @return
     * @throws IOException
     */
    public Identifiable getVersion(Identifier targetID, long version) throws IOException {

        DoubleHashMap<URI, Long> versionNumbers = getVersions(targetID);

        if (version == -1L) {
            version = getLatestVersionNumber(versionNumbers);
        }
        URI id = versionNumbers.getByValue(version);

        if (id == null) {
            return null;
        }
        return (Identifiable) getStore().get(BasicIdentifier.newID(id));

    }

    /**
     * Removed the version of the object from the store. This either returns
     * or throws a runtime exception from the store.
     * <h3>Note</h3>>
     * There is not a version with signature remove(Identifier) because of the
     * risk of removing the base object if the wrong .
     *
     * @param identifier
     * @param version
     */
    public void remove(Identifier identifier, long version) {
        Identifier versionedID = createVersionedID(identifier, version);
        getStore().remove(versionedID);
    }

    /**
     * Create a new version. This returns the overloaded identifier of the versioned object.
     *
     * @param identifier
     * @return
     */
    public Long create(Identifier identifier) {
        Identifiable identifiable = (Identifiable) getStore().get(identifier);
        Identifiable newVersion = getStore().create();
        XMLMap map = new XMLMap();

        MapConverter mc = getMapConverter();

        mc.toMap(identifiable, map);

        mc.fromMap(map, newVersion);
        DoubleHashMap<URI, Long> versions = getVersions(identifier);
        long newIndex = 0L;
        if (!versions.isEmpty()) {
            newIndex = getLatestVersionNumber(versions) + 1L;
        }
        Identifier newID = createVersionedID(identifiable.getIdentifier(), newIndex);
        newVersion.setIdentifier(newID);
        getStore().save(newVersion);
        return newIndex;
    }

    /**
     * Removes the fragment (with the version number).
     *
     * @param overloadedID
     * @return
     */
    public Identifier getBaseID(Identifier overloadedID) {
        String id = overloadedID.toString();
        return BasicIdentifier.newID(id.substring(0, id.indexOf('#')));
    }

    public List<Long> getVersionNumbers(Identifier id) {
        DoubleHashMap<URI, Long> versions = getVersions(id);
        List<Long> out = new ArrayList<>();
        out.addAll(versions.values());
        // sort list because generic store does not necessarily return versions in order
        Collections.sort(out);
        return out;
    }

    /**
     * For a
     * @param id
     * @param version
     * @return
     */
    public boolean restore(Identifier id, Long version){
        try {
            Identifiable identifiable = getVersion(id, version);
            identifiable.setIdentifier(id);
            getStore().save(identifiable);
            return Boolean.TRUE;
        } catch (IOException e) {
            return Boolean.FALSE;
        }

    }
    /*
        For testing -- get a couple of stores
    m:='oa2:/qdl/store';
    ini. := file_read('/home/ncsa/apps/qdl/apps/apps.ini', 2);
    a:=module_import(m, 'clients'); // don't want output
    a:=module_import(m, 'trans'); // don't want output
    clients#init(ini.stores.file, ini.stores.name, 'client');
    trans#init(ini.stores.file, ini.stores.name, 'transaction');
    // bunch of test clients. All are dummy clients
    clients#search('client_id', '.*234.*') =: c.
    trans#search('temp_token', '.*23.*') =: t.;

    cid := 'testScheme:oa4md,2018:/client_id/70e46ba17e8c4d00d30dd2345da83abe'
    clients#read(cid) =: x.
    clients#v_versions(c.6.client_id)


    // single store
     m:='oa2:/qdl/store';
    ini. := file_read('/home/ncsa/apps/qdl/apps/apps.ini', 2);
    a:=module_import(m, 'clients'); // don't want output
    clients#init(ini.stores.file, ini.stores.name, 'client');
    c. :=clients#search('client_id', '.*234.*')

     z := to_xml(c.0)
     c.0 == from_xml(z)

  x.error_uri := 'https://foo/error'
  x.scopes. := ['openid', 'info']
  x.callback_uri. := ['https://localhost/ready1','https://localhost/ready2']

// This computes for each, but sticks the result x. inside a [[x.]], hence the .0.0 at the end
      for_each(@==, clients#v_get(cid,0), clients#v_get(cid,1)).0.0

     */
}
