package eu.europa.esig.dss.xades.signature;

import static org.junit.Assert.assertEquals;

import org.junit.Ignore;
import org.junit.Test;

public class XAdESSignatureBuilderTest {

    @Test
    @Ignore("Added by Nortal DDS team. Tests implementation, functionality might not be needed")
    public void uriEncoding() {
        assertEquals("file.txt",
                XAdESSignatureBuilder.uriEncode("file.txt"));
        assertEquals("dds_J%C3%9CRI%C3%96%C3%96%20%E2%82%AC%20%C5%BE%C5%A0%20p%C3%A4ev.txt",
                XAdESSignatureBuilder.uriEncode("dds_JÜRIÖÖ € žŠ päev.txt"));
    }
}
