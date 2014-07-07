package eu.europa.ec.markt.dss.validation102853;

// TODO-Vin (07/07/2014): To be completed
public class TimestampInclude {

    private String uri;
    private boolean referencedData;

    public TimestampInclude(String uri, String referencedData) {
        this.uri = uri;
        this.referencedData = Boolean.parseBoolean(referencedData);
    }

    public String getURI() {
        return uri;
    }

    public void setURI(String uri) {
        this.uri = uri;
    }

    public boolean isReferencedData() {
        return referencedData;
    }

    public void setReferencedData(boolean referencedData) {
        this.referencedData = referencedData;
    }
}
