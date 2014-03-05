package eu.europa.ec.markt.dss.parameter;

import java.util.ArrayList;
import java.util.List;

/**
 * TODO
 *
 * <p> DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class DSSReference {

    private String id;
    private String uri;
    private String type;

    private List<DSSTransform> transforms;

    private String digestMethod;

    /**
     * The default constructor
     */
    public DSSReference() {
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getUri() {
        return uri;
    }

    public void setUri(String uri) {
        this.uri = uri;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public List<DSSTransform> getTransforms() {
        if (transforms == null) {
            transforms = new ArrayList<DSSTransform>();
        }
        return transforms;
    }

    public String getDigestMethod() {
        return digestMethod;
    }

    public void setDigestMethod(String digestMethod) {
        this.digestMethod = digestMethod;
    }
}
