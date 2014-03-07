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

package eu.europa.ec.markt.dss.validation102853.certificate;

import org.apache.commons.codec.binary.Hex;

/**
 * Reference a Certificate
 * 
 * 
 * @version $Revision: 3572 $ - $Date: 2014-03-06 19:08:51 +0100 (Thu, 06 Mar 2014) $
 */

public class CertificateRef {

   private String digestAlgorithm;
   private byte[] digestValue;
   private String issuerName;
   private String issuerSerial;

   /**
    * 
    * @return
    */
   public String getDigestAlgorithm() {
      return digestAlgorithm;
   }

   /**
    * 
    * @param digestAlgorithm
    */
   public void setDigestAlgorithm(String digestAlgorithm) {
      this.digestAlgorithm = digestAlgorithm;
   }

   /**
    * 
    * @return
    */
   public byte[] getDigestValue() {
      return digestValue;
   }

   /**
    * 
    * @param digestValue
    */
   public void setDigestValue(byte[] digestValue) {
      this.digestValue = digestValue;
   }

   /**
    * 
    * @return
    */
   public String getIssuerName() {
      return issuerName;
   }

   /**
    * 
    * @param issuerName
    */
   public void setIssuerName(String issuerName) {
      this.issuerName = issuerName;
   }

   /**
    * 
    * @return
    */
   public String getIssuerSerial() {
      return issuerSerial;
   }

   /**
    * 
    * @param issuerSerial
    */
   public void setIssuerSerial(String issuerSerial) {
      this.issuerSerial = issuerSerial;
   }

   @Override
   public String toString() {

      return "CertificateRef[issuerName=" + issuerName + ",issuerSerial=" + issuerSerial + ",digest=" + Hex.encodeHexString(digestValue) + "]";
   }
}
