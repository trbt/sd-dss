package eu.europa.ec.markt.dss.dao;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import eu.europa.ec.markt.dss.DSSUtils;
import eu.europa.ec.markt.dss.exception.DSSException;

/**
 * TODO
 *
 * <p>
 * DISCLAIMER: Project owner DG-MARKT.
 *
 * @author <a href="mailto:dgmarkt.Project-DSS@arhs-developments.com">ARHS Developments</a>
 * @version $Revision: 1016 $ - $Date: 2011-06-17 15:30:45 +0200 (Fri, 17 Jun 2011) $
 */
public class ProxyFileDao implements ProxyDao {

    protected Map<ProxyKey, ProxyPreference> proxyPreferences = new HashMap<ProxyKey, ProxyPreference>();

    public ProxyFileDao(final String proxyPreferencesResourcePath) {

        System.out.println("############# " + proxyPreferencesResourcePath);
        try {

            final InputStream propertyInputStream = DSSUtils.getResource(proxyPreferencesResourcePath);
            final Properties properties = new Properties();
            properties.load(propertyInputStream);
            for (final Map.Entry keySet : properties.entrySet()) {

                final String key = (String) keySet.getKey();
                final String value = (String) keySet.getValue();
                System.out.println(key + "=" + value);
                final ProxyKey proxyKey = ProxyKey.fromKey(key);
                if (proxyKey == null) {
                    continue;
                }
                final ProxyPreference proxyPreference = new ProxyPreference(proxyKey, value);
                proxyPreferences.put(proxyKey, proxyPreference);
            }
        } catch (IOException e) {
            throw new DSSException("Error when initialising ProxyFileDao", e);
        }
    }

    @Override
    public ProxyPreference get(final ProxyKey proxyKey) {

        final ProxyPreference proxyPreference = proxyPreferences.get(proxyKey);
        return proxyPreference;
    }

    @Override
    public Collection<ProxyPreference> getAll() {

        List<ProxyPreference> proxyPreferenceList = new ArrayList<ProxyPreference>(proxyPreferences.values());
        return proxyPreferenceList;
    }

    @Override
    public void update(final ProxyPreference proxyPreference) {

        proxyPreferences.put(proxyPreference.getProxyKey(), proxyPreference);
    }
}
