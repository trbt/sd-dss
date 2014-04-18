package eu.europa.ec.markt.dss.parameter;

import eu.europa.ec.markt.dss.validation102853.SignatureForm;

/**
 * This class regroups the signature parameters related to ASiC form.
 * <p/>
 * <p/>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ASiCParameters {

    private boolean asicComment = false;

    /**
     * The default signature form to use within the ASiC containers.
     */
    private SignatureForm asicSignatureForm = SignatureForm.XAdES;

    public ASiCParameters() {
    }

    public ASiCParameters(final ASiCParameters source) {

        asicComment = source.asicComment;
        asicSignatureForm = source.asicSignatureForm;

    }

    public boolean isAsicComment() {
        return asicComment;
    }

    /**
     * This method allows to indicate if the zip comment will contain the mime type.
     *
     * @param asicComment
     */
    public void setAsicComment(final boolean asicComment) {
        this.asicComment = asicComment;
    }

    public SignatureForm getAsicSignatureForm() {
        return asicSignatureForm;
    }

    /**
     * Sets the signature form associated with an ASiC container. Only two forms are acceptable: XAdES and CAdES.
     *
     * @param asicSignatureForm signature form to associate with the ASiC container.
     */
    public void setAsicSignatureForm(final SignatureForm asicSignatureForm) {
        this.asicSignatureForm = asicSignatureForm;
    }

}
