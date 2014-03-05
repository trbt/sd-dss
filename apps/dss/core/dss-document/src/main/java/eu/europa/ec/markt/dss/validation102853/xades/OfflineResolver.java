/*
 * Copyright  1999-2004 The Apache Software Foundation.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package eu.europa.ec.markt.dss.validation102853.xades;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignatureInput;
import org.apache.xml.security.utils.resolver.ResourceResolverContext;
import org.apache.xml.security.utils.resolver.ResourceResolverException;
import org.apache.xml.security.utils.resolver.ResourceResolverSpi;
import org.apache.xml.utils.URI;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Attr;

import eu.europa.ec.markt.dss.signature.DSSDocument;
import eu.europa.ec.markt.dss.signature.MimeType;

/**
 * This class helps us home users to resolve http URIs without a network connection
 *
 * @author $Author$
 */
public class OfflineResolver extends ResourceResolverSpi {

    /**
     * {@link org.apache.commons.logging} logging facility
     */
    private static final Logger LOG = LoggerFactory.getLogger(OfflineResolver.class);

    private final String documentURI;

    private final DSSDocument document;

    /**
     * Field uriMap
     */
    static Map uriMap = null;

    /**
     * Field mimeMap
     */
    static Map mimeMap = null;

    /**
     * Method register
     *
     * @param uri
     * @param fileName
     * @param mime
     */
    private static void register(final String uri, final String fileName, final String mime) {

        OfflineResolver.uriMap.put(uri, fileName);
        OfflineResolver.mimeMap.put(uri, mime);
    }

    static {

        Init.init();

        OfflineResolver.uriMap = new HashMap();
        OfflineResolver.mimeMap = new HashMap();

        // OfflineResolver.register("http://www.w3.org/TR/xml-stylesheet", "data/org/w3c/www/TR/xml-stylesheet.html", "text/html");
    }

    public OfflineResolver(final DSSDocument document) {

        this.documentURI = (document != null) ? document.getName() : null;
        this.document = document;
    }

    @Override
    public boolean engineCanResolveURI(final ResourceResolverContext context) {

        final Attr uriAttr = context.attr;
        final String baseUriString = context.baseUri;

        String uriNodeValue = uriAttr.getNodeValue();
        if (uriNodeValue.equals("") || uriNodeValue.startsWith("#")) {
            return false;
        }
        try {

            // TODO: Following the test case: XAdESTest003 test: testTDetached() the URI can be like: should we accept this URI and what about the baseURI ?
            // <ds:Reference Id="Reference0" URI="./TARGET_BBB.bin">
            // The following rule was added to comply this functionality:
            // BEGIN:
            if (uriNodeValue.startsWith("./")) {

                uriNodeValue = uriNodeValue.substring(2);
            }
            // :END
            // TODO: (Bob: 2014 Feb 08) Adaptation for AT. These rules should be executed if the standard dereferencing does not work. To be moved.
            // BEGIN:
            if (uriNodeValue.startsWith("file:")) {

                uriNodeValue = uriNodeValue.substring(5);
            }
            if (uriNodeValue.startsWith("urn:Document")) {

                uriNodeValue = documentURI;
            }
            // :END

            if (uriNodeValue.equals(documentURI)) {

                LOG.debug("I state that I can resolve '" + uriNodeValue.toString() + "' (external document)");
                return true;
            }
            final URI baseUri = new URI(baseUriString);
            URI uriNew = new URI(baseUri, uriNodeValue);
            if (uriNew.getScheme().equals("http")) {

                LOG.debug("I state that I can resolve '" + uriNew.toString() + "'");
                return true;
            }
            LOG.debug("I state that I can't resolve '" + uriNew.toString() + "'");
        } catch (URI.MalformedURIException ex) {
            ex.printStackTrace();
        }

        return false;
    }

    @Override
    public XMLSignatureInput engineResolveURI(ResourceResolverContext context) throws ResourceResolverException {

        final Attr uriAttr = context.attr;
        final String baseUriString = context.baseUri;
        try {

            String uriNodeValue = uriAttr.getNodeValue();
            // TODO: Following the test case: XAdESTest003 test: testTDetached() the URI can be like: should we accept this URI and what about the baseURI ?
            // <ds:Reference Id="Reference0" URI="./TARGET_BBB.bin">
            // The following rule was added to comply this functionality:
            // BEGIN:
            if (uriNodeValue.startsWith("./")) {

                uriNodeValue = uriNodeValue.substring(2);
            }
            // :END
            // TODO: (Bob: 2014 Feb 08) Adaptation for AT
            // BEGIN:
            if (uriNodeValue.startsWith("file:")) {

                uriNodeValue = uriNodeValue.substring(5);
            }
            if (uriNodeValue.startsWith("urn:Document")) {

                uriNodeValue = documentURI;
            }
            // :END
            if (OfflineResolver.uriMap.containsKey(uriNodeValue)) {

                String newURI = (String) OfflineResolver.uriMap.get(uriNodeValue);

                LOG.debug("Mapped " + uriNodeValue + " to " + newURI);

                InputStream is = new FileInputStream(newURI);

                LOG.debug("Available bytes = " + is.available());

                XMLSignatureInput result = new XMLSignatureInput(is);

                // XMLSignatureInput result = new XMLSignatureInput(inputStream);
                result.setSourceURI(uriNodeValue);
                result.setMIMEType((String) OfflineResolver.mimeMap.get(uriNodeValue));

                return result;
            } else if (uriNodeValue.equals(documentURI)) {

                final byte[] bytes = document.getBytes();
                LOG.debug("Available bytes = " + bytes.length);
                XMLSignatureInput result = new XMLSignatureInput(bytes);
                result.setSourceURI(uriNodeValue);
                final MimeType mimeType = document.getMimeType();
                if (mimeType != null) {
                    result.setMIMEType(mimeType.getCode());
                }
                return result;
            } else {

                Object exArgs[] = {"The uriNodeValue " + uriNodeValue + " is not configured for offline work"};
                throw new ResourceResolverException("generic.EmptyMessage", exArgs, uriAttr, baseUriString);
            }
        } catch (IOException ex) {
            throw new ResourceResolverException("generic.EmptyMessage", ex, uriAttr, baseUriString);
        }
    }
}