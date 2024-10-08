/**
 * This package contains all of the storage classes for an OA4MP client.
 * <h2>Usage</h2>
 * While it is possible to create instances directly, the most normal usage is to simply
 * use the {@link AssetStore} interface and the {@link org.oa4mp.client.api.ClientEnvironment#getAssetStore()}
 * method which configures the store directly from the configuration file. The various implementation of this
 * interface correspond to the underlying storage mechanism (e.g. {@link FSAssetStore} which is backed by the file system.)
 */
package org.oa4mp.client.api.storage;
