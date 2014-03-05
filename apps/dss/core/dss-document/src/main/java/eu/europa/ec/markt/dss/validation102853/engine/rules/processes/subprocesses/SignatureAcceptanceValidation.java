/*
 * DSS - Digital Signature Services
 *
 * Copyright (C) 2013 European Commission, Directorate-General Internal Market and Services (DG MARKT), B-1049 Bruxelles/Brussel
 *
 * Developed by: 2013 ARHS Developments S.A. (rue Nicolas Bové 2B, L-1253 Luxembourg) http://www.arhs-developments.com
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

package eu.europa.ec.markt.dss.validation102853.engine.rules.processes.subprocesses;

import java.util.List;

import eu.europa.ec.markt.dss.exception.DSSException;
import eu.europa.ec.markt.dss.validation102853.TimestampType;
import eu.europa.ec.markt.dss.validation102853.engine.rules.wrapper.ValidationPolicy;
import eu.europa.ec.markt.dss.validation102853.xml.XmlDom;
import eu.europa.ec.markt.dss.validation102853.xml.XmlNode;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeName;
import eu.europa.ec.markt.dss.validation102853.rules.AttributeValue;
import eu.europa.ec.markt.dss.validation102853.rules.ExceptionMessage;
import eu.europa.ec.markt.dss.validation102853.rules.Indication;
import eu.europa.ec.markt.dss.validation102853.rules.NodeName;
import eu.europa.ec.markt.dss.validation102853.rules.NodeValue;
import eu.europa.ec.markt.dss.validation102853.engine.rules.ProcessParameters;
import eu.europa.ec.markt.dss.validation102853.RuleUtils;
import eu.europa.ec.markt.dss.validation102853.rules.SubIndication;

public class SignatureAcceptanceValidation implements Indication, SubIndication, NodeName, NodeValue, AttributeName, AttributeValue, ExceptionMessage {

    /**
     * The following variables are used only in order to simplify the writing of the rules!
     */

    /**
     * See {@link ProcessParameters#getValidationPolicy()}
     */
    private ValidationPolicy constraintData;

    /**
     * See {@link ProcessParameters#getSignatureContext()}
     */
    private XmlDom signatureContext;

    /**
     * This node is used to add the constraint nodes.
     */
    private XmlNode subProcessNode;

    private void prepareParameters(final ProcessParameters params) {

        this.constraintData = params.getValidationPolicy();

        this.signatureContext = params.getSignatureContext();

        isInitialised();
    }

    private void isInitialised() {

        if (constraintData == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "validationPolicy"));
        }
        if (signatureContext == null) {
            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "signatureContext"));
        }
    }

    public boolean run(final ProcessParameters params, final XmlNode processNode) {

        if (processNode == null) {

            throw new DSSException(String.format(EXCEPTION_TCOPPNTBI, getClass().getSimpleName(), "processNode"));
        }
        prepareParameters(params);

        /**
         * 5.5 Signature Acceptance Validation (SAV)
         */

        subProcessNode = processNode.addChild(SAV);
        final XmlNode conclusionNode = new XmlNode(CONCLUSION);

        final boolean valid = process(params, conclusionNode);

        if (valid) {

            conclusionNode.addChild(INDICATION, VALID);
            conclusionNode.setParent(subProcessNode);
        } else {

            subProcessNode.addChild(conclusionNode);
            processNode.addChild(conclusionNode);
        }
        return valid;
    }

    /**
     * @param params
     * @param conclusionNode
     * @return
     */
    private boolean process(final ProcessParameters params, final XmlNode conclusionNode) {

        /**
         * This process consists in checking the Signature and Cryptographic Constraints against the signature. The
         * general principle is as follows: perform the following for each constraint:
         *
         * • If the constraint necessitates processing a property/attribute in the signature, perform the processing of
         * the property/attribute as specified from clause 5.5.4.1 to 5.5.4.8.
         *
         * 5.5.4.1 Processing AdES properties/attributes This clause describes the application of Signature Constraints on
         * the content of the signature including the processing on signed and unsigned properties/attributes.
         *
         * <SigningCertificateChainConstraint><br>
         * <MandatedSignedQProperties>
         *
         * Indicates the mandated signed qualifying properties that are mandated to be present in the signature. This
         * includes:
         *
         * • signing-time
         */

        final boolean checkIfSigningTimeIsPresent = constraintData.shouldCheckIfSigningTimeIsPresent();
        if (checkIfSigningTimeIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPSTP_LABEL, BBB_SAV_ISQPSTP);

            final String signingTime = signatureContext.getValue("./DateTime/text()");
            if (signingTime.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, BBB_SAV_ISQPSTP_ANS_LABEL);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, signingTime).setAttribute(FIELD, SIGNING_TIME);
        }

        /**
         * • content-hints<br>
         */

        final boolean checkIfContentHintsIsPresent = constraintData.shouldCheckIfContentHintsIsPresent();
        if (checkIfContentHintsIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPCHP_LABEL, BBB_SAV_ISQPCHP);

            final String contentHints = signatureContext.getValue("./ContentHints/text()");
            if (contentHints.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, BBB_SAV_ISQPCHP_ANS_LABEL);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, contentHints).setAttribute(FIELD, CONTENT_HINTS);
        }

        /**
         * • content-reference<br>
         */

        /**
         * • content-identifier
         */
        final boolean checkIfContentIdentifierIsPresent = constraintData.shouldCheckIfContentIdentifierIsPresent();
        if (checkIfContentIdentifierIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPCIP_LABEL, BBB_SAV_ISQPCIP);

            final String contentIdentifier = signatureContext.getValue("./ContentIdentifier/text()");
            if (contentIdentifier.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, BBB_SAV_ISQPCIP_ANS_LABEL);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, contentIdentifier).setAttribute(FIELD, CONTENT_IDENTIFIER);
        }

        /**
         * • content type
         */
        final boolean checkIfContentTypeIsPresent = constraintData.shouldCheckIfContentTypeIsPresent();
        if (checkIfContentTypeIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPCTP_LABEL, BBB_SAV_ISQPCTP);

            final String contentType = signatureContext.getValue("./ContentType/text()");
            if (contentType.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, BBB_SAV_ISQPCTP_ANS_LABEL);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, contentType).setAttribute(FIELD, CONTENT_TYPE);
        }

        /**
         * • commitment-type-indication
         */
        final boolean checkIfCommitmentTypeIndicationIsPresent = constraintData.shouldCheckIfCommitmentTypeIndicationIsPresent();
        if (checkIfCommitmentTypeIndicationIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPXTIP_LABEL, BBB_SAV_ISQPXTIP);
            ///final List<XmlDom> commitmentTypeIndications = signatureContext.getElements("./CommitmentTypeIndication/Identifier");
            final String commitment_type_indication = signatureContext.getValue("./CommitmentTypeIndication/Identifier/text()");
            final List<String> commitmentTypeIndications = constraintData.getCommitmentTypeIndications();
            final boolean contains = RuleUtils.contains1(commitment_type_indication, commitmentTypeIndications);
            if (!contains) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, commitment_type_indication).setAttribute(FIELD, COMMITMENT_TYPE_INDICATION_IDENTIFIER);
        }

        /**
         * • signer-location
         */

        final boolean checkIfSignerLocationIsPresent = constraintData.shouldCheckIfSignerLocationIsPresent();
        if (checkIfSignerLocationIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPSLP_LABEL, BBB_SAV_ISQPSLP);

            final XmlDom signProductionPlaceXmlDom = signatureContext.getElement("./SignatureProductionPlace");
            String signProductionPlace = "";
            if (signProductionPlaceXmlDom != null) {

                final List<XmlDom> elements = signProductionPlaceXmlDom.getElements("./*");
                for (final XmlDom element : elements) {

                    if (!signProductionPlace.isEmpty()) {

                        signProductionPlace += "; ";
                    }
                    signProductionPlace += element.getName() + ": " + element.getText();
                }
            }
            if (signProductionPlace.isEmpty()) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, signProductionPlace).setAttribute(FIELD, SIGNATURE_PRODUCTION_PLACE);
        }

        /**
         * • signer-attributes<br>
         */
        /**
         * • content-time-stamp
         */
        final boolean checkIfContentTimeStampIsPresent = constraintData.shouldCheckIfContentTimeStampIsPresent();
        if (checkIfContentTimeStampIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ISQPCTSIP_LABEL, BBB_SAV_ISQPCTSIP);
            final long count = signatureContext.getCountValue("count(./Timestamps/Timestamp[@Type='%s'])", TimestampType.CONTENT_TIMESTAMP);
            if (count <= 0) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, BBB_SAV_ISQPCTSIP_ANS_LABEL);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
        }

        /**
         * <MandatedUnsignedQProperties>
         *
         * ../..
         *
         * <OnRoles>
         */

        final boolean checkIfClaimedRoleIsPresent = constraintData.shouldCheckIfClaimedRoleIsPresent();
        if (checkIfClaimedRoleIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ICRM_LABEL, BBB_SAV_ICRM);

            final List<String> requestedClaimedRoles = constraintData.getClaimedRoles();
            final String requestedClaimedRolesString = RuleUtils.toString(requestedClaimedRoles);

            final List<XmlDom> claimedRolesXmlDom = signatureContext.getElements("./ClaimedRoles/ClaimedRole");
            final List<String> claimedRoles = RuleUtils.toStringList(claimedRolesXmlDom);
            final String claimedRolesString = RuleUtils.toString(claimedRoles);

            String attendance = constraintData.getCertifiedRolesAttendance();
            if (!"ANY".equals(attendance)) {

                boolean contains = RuleUtils.contains(requestedClaimedRoles, claimedRoles);

                if (!contains) {

                    constraintNode.addChild(STATUS, KO);
                    conclusionNode.addChild(INDICATION, INVALID);
                    conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                    conclusionNode.addChild(INFO, claimedRolesString).setAttribute(FIELD, CLAIMED_ROLES);
                    conclusionNode.addChild(INFO, requestedClaimedRolesString).setAttribute(FIELD, REQUESTED_ROLES);
                    return false;
                }
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, claimedRolesString).setAttribute(FIELD, CLAIMED_ROLES);
        }

        /**
         * 5.5.4.2 Processing signing certificate reference constraint<br>
         * If the SigningCertificate property contains references to other certificates in the path, the verifier shall
         * check each of the certificates in the certification path against these references as specified in steps 1 and 2
         * in clause 5.1.4.1 (resp clause 5.1.4.2) for XAdES (resp CAdES). Should this property contain one or more
         * references to certificates other than those present in the certification path, the verifier shall assume that a
         * failure has occurred during the verification. Should one or more certificates in the certification path not be
         * referenced by this property, the verifier shall assume that the verification is successful unless the signature
         * policy mandates that references to all the certificates in the certification path "shall" be present.
         *
         * ../..
         *
         * 5.5.4.3 Processing claimed signing time<br>
         * If the signature constraints contain constraints regarding this property, the verifying application shall
         * follow its rules for checking this signed property. Otherwise, the verifying application shall make the value
         * of this property/attribute available to its DA, so that it may decide additional suitable processing, which is
         * out of the scope of the present document.
         *
         * ../..
         */

        /**
         * 5.5.4.6 Processing Time-stamps on signed data objects<br>
         * If the signature constraints contain specific constraints for content-time-stamp attributes, the SVA shall
         * check that they are satisfied. To do so, the SVA shall do the following steps for each content-time-stamp
         * attribute:<br>
         * 1) Perform the Validation Process for AdES Time-Stamps as defined in clause 7 with the time-stamp token of the
         * content-time-stamp attribute.<br>
         * 2) Check the message imprint: check that the hash of the signed data obtained using the algorithm indicated in
         * the time-stamp token matches the message imprint indicated in the token.<br>
         * 3) Apply the constraints for content-time-stamp attributes to the results returned in the previous steps. If
         * any check fails, return INVALID/SIG_CONSTRAINTS_FAILURE with an explanation of the unverified constraint.
         */

        // The DSS framework doesn't handle at the level of the signature constraints any specific constraints for
        // content-time-stamp attributes.

        /**
         5.5.4.7 Processing Countersignatures
         If the signature constraints define specific constraints for countersignature attributes, the SVA shall check that they are
         satisfied. To do so, the SVA shall do the following steps for each countersignature attribute:
         1) Perform the validation process for AdES-BES/EPES using the countersignature in the property/attribute and
         the signature value octet string of the signature as the signed data object.
         2) Apply the constraints for countersignature attributes to the result returned in the previous step. If any check
         fails, return INVALID/SIG_CONSTRAINTS_FAILURE with an explanation of the unverified constraint.
         If the signature constraints do not contain any constraint on countersignatures, the SVA may still verify the
         countersignature and provide the results in the validation report. However, it shall not consider the signature validation
         to having failed if the countersignature could not be verified.
         */

        /**
         *
         5.5.4.8 Processing signer attributes/roles
         If the signature constraints define specific constraints for certified attributes/roles, the SVA shall perform the following
         checks:
         1) The SVA shall verify the validity of the attribute certificate(s) present in this property/attribute following the
         rules established in [6].
         2) The SVA shall check that the attribute certificate(s) actually match the rules specified in the input constraints.
         If the signature rules do not specify rules for certified attributes/roles, the SVA shall make the value of this
         property/attribute available to its DA so that it may decide additional suitable processing, which is out of the scope of
         the present document.
         */

        final boolean checkIfCertifiedRoleIsPresent = constraintData.shouldCheckIfCertifiedRoleIsPresent();
        if (checkIfCertifiedRoleIsPresent) {

            final XmlNode constraintNode = addConstraint(BBB_SAV_ICERRM_LABEL, BBB_SAV_ICERRM);

            final List<String> requestedCertifiedRoles = constraintData.getCertifiedRoles();
            final String requestedCertifiedRolesString = RuleUtils.toString(requestedCertifiedRoles);

            final List<XmlDom> certifiedRolesXmlDom = signatureContext.getElements("./CertifiedRoles/CertifiedRole");
            final List<String> certifiedRoles = RuleUtils.toStringList(certifiedRolesXmlDom);
            final String certifiedRolesString = RuleUtils.toString(certifiedRoles);

            boolean contains = RuleUtils.contains(requestedCertifiedRoles, certifiedRoles);

            if (!contains) {

                constraintNode.addChild(STATUS, KO);
                conclusionNode.addChild(INDICATION, INVALID);
                conclusionNode.addChild(SUB_INDICATION, SIG_CONSTRAINTS_FAILURE);
                conclusionNode.addChild(INFO, certifiedRolesString).setAttribute(FIELD, CERTIFIED_ROLES);
                conclusionNode.addChild(INFO, requestedCertifiedRolesString).setAttribute(FIELD, REQUESTED_ROLES);
                return false;
            }
            constraintNode.addChild(STATUS, OK);
            constraintNode.addChild(INFO, certifiedRolesString).setAttribute(FIELD, CERTIFIED_ROLES);
            constraintNode.addChild(INFO, "WARNING: The attribute certificate is not cryptographically validated.");
        }

        /**
         * ../..
         * 5.5.4 Processing
         * ../..
         * • If at least one of the algorithms that have been used in validation of the signature or the size of the keys
         * used with such an algorithm is no longer considered reliable, return
         * INDETERMINATE/CRYPTO_CONSTRAINTS_FAILURE_NO_POE together with the list of algorithms and key sizes, if
         * applicable, that are concerned and the time for each of the algorithms up to which the resp. algorithm was
         * considered secure.
         */
        final XmlNode constraintNode = addConstraint(BBB_SAV_ASCCM_LABEL, BBB_SAV_ASCCM);

        final SAVCryptographicConstraint cryptoConstraints = new SAVCryptographicConstraint();
        final SAVCryptoConstraintParameters cryptoParams = new SAVCryptoConstraintParameters(params, SIGNATURE_TO_VALIDATE);
        final XmlNode infoContainerNode = new XmlNode("Container");
        final boolean cryptographicStatus = cryptoConstraints.run(cryptoParams, infoContainerNode);
        if (cryptographicStatus) {

            constraintNode.addChild(STATUS, OK);
        } else {

            constraintNode.addChild(STATUS, KO);
            conclusionNode.addChild(INDICATION, INDETERMINATE);
            conclusionNode.addChild(SUB_INDICATION, CRYPTO_CONSTRAINTS_FAILURE_NO_POE);
            conclusionNode.addChildrenOf(infoContainerNode);
            return false;
        }
        return true;
    }

    /**
     * @param label
     * @param nameId
     * @return
     */
    private XmlNode addConstraint(final String label, final String nameId) {

        final XmlNode constraintNode = subProcessNode.addChild(CONSTRAINT);
        constraintNode.addChild(NAME, label).setAttribute(NAME_ID, nameId);
        return constraintNode;
    }
}
