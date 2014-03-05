package eu.europa.ec.markt.dss.validation102853.bean;

import java.util.ArrayList;
import java.util.List;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class CommitmentType {

    private List<String> identifiers;

    public List<String> getIdentifiers() {
        return identifiers;
    }

    public void addIdentifier(final String identifier) {

        if (identifiers == null) {

            identifiers = new ArrayList<String>();
        }
        identifiers.add(identifier);
    }
}
