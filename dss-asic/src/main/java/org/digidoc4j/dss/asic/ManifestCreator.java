/**
 * DSS - Digital Signature Services
 * Copyright (C) 2015 European Commission, provided under the CEF programme
 *
 * This file is part of the "DSS - Digital Signature Services" project.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */
package org.digidoc4j.dss.asic;

import eu.europa.esig.dss.DSSDocument;
import eu.europa.esig.dss.DSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

public class ManifestCreator {

    private static final Logger LOG = LoggerFactory.getLogger(ManifestCreator.class);

    public static void storeManifest(DSSDocument document, ZipOutputStream outZip) {
        LOG.debug("Storing META-INF/manifest.xml");
        Manifest manifest = new Manifest();
        manifest.addFileEntry(document);
        try {
            outZip.putNextEntry(new ZipEntry(Manifest.XML_PATH));
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            manifest.save(out);
            outZip.write(out.toByteArray());
        } catch (IOException e) {
            LOG.error(e.getMessage());
            throw new DSSException(e);
        }
    }
}
