/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2011 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2011 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * "DSS - Digital Signature Services" is free software: you can redistribute it and/or modify it under the terms of
 * the GNU Lesser General Public License as published by the Free Software Foundation, either version 2.1 of the
 * License, or (at your option) any later version.
 *
 * DSS is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
 * of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License along with
 * "DSS - Digital Signature Services".  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.europa.ec.markt.dss;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.InputStreamEntity;
import org.apache.http.util.EntityUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import eu.europa.ec.markt.dss.exception.DSSCannotFetchDataException;
import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation.https.CommonsHttpDataLoader;

public class FileCacheHttpDataLoader extends CommonsHttpDataLoader {

    private static final Logger LOG = LoggerFactory.getLogger(FileCacheHttpDataLoader.class);

    private File fileCacheDirectory = new File(System.getProperty("java.io.tmpdir"));

    private TestResourceLoader resourceLoader = new TestResourceLoader();

    private List<String> toBeLoaded;

    public void setFileCacheDirectory(File fileCacheDirectory) {
        this.fileCacheDirectory = fileCacheDirectory;
        this.fileCacheDirectory.mkdirs();
    }

    public void setResourceLoader(final TestResourceLoader resourceLoader) {
        this.resourceLoader = resourceLoader;
    }

    public void addToBeLoaded(String url) {

        if (toBeLoaded == null) {

            toBeLoaded = new ArrayList<String>();
        }
        toBeLoaded.add(url);
    }

    @Override
    public byte[] get(final String url) throws DSSCannotFetchDataException {

        if (toBeLoaded != null) {

            if (!toBeLoaded.contains(url)) {

                return null;
            }
        }
        final String fileName = TestResourceLoader.getNormalizedFileName(url);
        final File file = getCacheFile(fileName);
        if (file.exists()) {

            final byte[] bytes = DSSUtils.toByteArray(file);
            return bytes;
        }
        final byte[] returnedBytes;
        final String normalizedUrl = url.trim().toLowerCase();
        if (!normalizedUrl.startsWith("http")) {

            final String resourcePath = resourceLoader.getAbsoluteResourceFolder(url.trim());
            final File fileResource = new File(resourcePath);
            returnedBytes = DSSUtils.toByteArray(fileResource);
        } else {

            returnedBytes = getHttpGetResponse(url);
        }
        if (returnedBytes.length != 0) {

            final File out = getCacheFile(fileName);
            DSSUtils.saveToFile(returnedBytes, out);
        }
        return returnedBytes;
    }

    private File getCacheFile(final String fileName) {

        LOG.debug("Cached file: " + fileCacheDirectory + "/" + fileName);
        return new File(fileCacheDirectory, fileName);
    }

    private byte[] getHttpGetResponse(final String url) throws DSSException {

        HttpGet httpGet = null;
        HttpEntity entity = null;
        try {

            final HttpClient httpClient = getHttpClient(url);
            final URI uri = URI.create(url.trim());
            httpGet = new HttpGet(uri);
            final HttpResponse httpResponse = httpClient.execute(httpGet);
            final int statusCode = httpResponse.getStatusLine().getStatusCode();
            if (statusCode == HttpStatus.SC_OK) {

                entity = httpResponse.getEntity();
                final byte[] content = getContent(entity);
                return content;
            } else {

                LOG.info("get '{}': status: {}", url, statusCode);
                return new byte[0];
            }
        } catch (IOException e) {
            throw new DSSException(e);
        } finally {
            if (httpGet != null) {
                httpGet.releaseConnection();
            }
            if (entity != null) {
                EntityUtils.consumeQuietly(entity);
            }
        }
    }

    @Override
    public byte[] post(final String url, final byte[] content) throws DSSException {

        final String fileName = TestResourceLoader.getNormalizedFileName(url);

        // The length for the InputStreamEntity is needed, because some receivers (on the other side) need this
        // information.
        // To determine the length, we cannot read the content-stream up to the end and re-use it afterwards.
        // This is because, it may not be possible to reset the stream (= go to position 0).
        // So, the solution is to cache temporarily the complete content data (as we do not expect much here) in a
        // byte-array.
        final byte[] digest = DSSUtils.digest(DigestAlgorithm.MD5, content);
        final String digestHexEncoded = DSSUtils.toHex(digest);
        final String cacheFileName = fileName + "." + digestHexEncoded;
        LOG.debug("Cache file name: " + cacheFileName);

        final File file = getCacheFile(cacheFileName);
        if (file.exists()) {

            LOG.debug("Cache file used");
            final byte[] byteArray = DSSUtils.toByteArray(file);
            return byteArray;
        }

        final byte[] returnedBytes;
        final String normalizedUrl = url.trim().toLowerCase();
        if (!normalizedUrl.startsWith("http")) {

            final String resourcePath = resourceLoader.getAbsoluteResourceFolder(url.trim());
            final File fileResource = new File(resourcePath);
            returnedBytes = DSSUtils.toByteArray(fileResource);
            return returnedBytes;
        }

        HttpPost httpRequest = null;
        HttpResponse httpResponse = null;
        try {

            final URI uri = URI.create(url.trim());
            httpRequest = new HttpPost(uri);

            final ByteArrayInputStream bis = new ByteArrayInputStream(content);

            final HttpEntity requestEntity = new InputStreamEntity(bis, content.length);
            httpRequest.setEntity(requestEntity);
            if (contentType != null) {
                httpRequest.setHeader(CONTENT_TYPE, contentType);
            }

            httpResponse = super.getHttpResponse(httpRequest, url);

            returnedBytes = readHttpResponse(url, httpResponse);
            if (returnedBytes.length != 0) {

                final File cacheFile = getCacheFile(cacheFileName);
                DSSUtils.saveToFile(returnedBytes, cacheFile);
            }
        } finally {
            if (httpRequest != null) {
                httpRequest.releaseConnection();
            }
            if (httpResponse != null) {
                EntityUtils.consumeQuietly(httpResponse.getEntity());
            }
        }
        return returnedBytes;
    }
}
