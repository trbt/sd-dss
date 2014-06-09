package eu.europa.ec.markt.dss.validation102853;

import java.util.Date;

/**
 * This class allows to associate a specific date to the validation process.
 */
public class CustomDateProcessExecutor extends ProcessExecutor {

    /**
     * The default constructor.
     *
     * @param validationDate specific validation date
     */
    public CustomDateProcessExecutor(final Date validationDate) {

        currentTime = validationDate;
    }
}
