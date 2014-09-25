/*
 * Licensed to the University Corporation for Advanced Internet Development, 
 * Inc. (UCAID) under one or more contributor license agreements.  See the 
 * NOTICE file distributed with this work for additional information regarding
 * copyright ownership. The UCAID licenses this file to You under the Apache 
 * License, Version 2.0 (the "License"); you may not use this file except in 
 * compliance with the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package edu.internet2.middleware.ant.pki;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.GregorianCalendar;

import org.apache.tools.ant.BuildException;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.Task;
import org.apache.tools.ant.types.EnumeratedAttribute;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.asn1.x509.X509Name;
import org.bouncycastle.openssl.PEMWriter;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.bouncycastle.x509.extension.SubjectKeyIdentifierStructure;

/**
 * An ant task that generates a self-signed certificate.
 * 
 * This ant task requires three attributes:
 * <ul>
 * <li><strong>hostname</strong> - the server hostname that will be used in the certificate Subject and Issuer DN</li>
 * </ul>
 * 
 * The task also has two optional attributes:
 * <ul>
 * <li><strong>keyType</strong> - type of key generated, possible values are "DSA" or "RSA", the default is RSA</li>
 * <li><strong>keySize</strong> - size, in bits, of the generated key, default is 2048</li>
 * <li><strong>privateKeyFile</strong> - file to which the generated private key will be written, in PEM format</li>
 * <li><strong>certifcateFile</strong> - file to which the self-signed certificate will be written, in PEM format</li>
 * <li><strong>keystoreFile</strong> - keystore to which the self-signed certificate and key will be written</li>
 * <li><strong>keystorePassword</strong> - password for the keystore, if none is given the string 'changeit' is used</li>
 * <li><strong>dnsSubjectAltNames</strong> - space separated list of DNS subject alt names</li>
 * <li><strong>uriSubjectAltNames</strong> - space separated list of URI subject alt names</li>
 * <ul>
 */
public class SelfSignedCertificate extends Task {

    /** Type of key to generated. Valid values: DSA or RSA */
    private String keyType = "RSA";

    /** Size of the generated key. */
    private int keysize = 2048;

    /** Number of years before the self-signed certificate expires. */
    private int certificateLifetime = 20;

    /** Hostname that will appear as the certifcate's DN common name component. */
    private String hostname;

    /** Optional DNS subject alt names. */
    private String[] dnsSubjectAltNames;

    /** Optional DNS subject alt names. */
    private String[] uriSubjectAltNames;

    /** File to which the public key will be written. */
    private File privateKeyFile;

    /** File to which the certificate will be written. */
    private File certificateFile;

    /** File to which the keystore will be written. */
    private File keystoreFile;

    /** Password for the generated keystore. */
    private String keystorePassword;

    /** {@inheritDoc} */
    public void execute() throws BuildException {
        validate();
        KeyPair keypair = generateKeyPair();
        X509Certificate certificate = generateCertificate(keypair);

        if (privateKeyFile != null) {
            try {
                privateKeyFile.createNewFile();
                PEMWriter keyOut = new PEMWriter(new FileWriter(privateKeyFile));
                keyOut.writeObject(keypair.getPrivate());
                keyOut.flush();
                keyOut.close();
            } catch (Exception e) {
                throw new BuildException("Unable to create private key file.", e);
            }
        }

        if (certificateFile != null) {
            try {
                certificateFile.createNewFile();
                PEMWriter certOut = new PEMWriter(new FileWriter(certificateFile));
                certOut.writeObject(certificate);
                certOut.flush();
                certOut.close();
            } catch (Exception e) {
                throw new BuildException("Unable to create private key file.", e);
            }
        }

        if (keystoreFile != null) {
            try {
                KeyStore store = KeyStore.getInstance("JKS");
                store.load(null, null);
                store.setKeyEntry(hostname, keypair.getPrivate(), keystorePassword.toCharArray(),
                        new X509Certificate[] {certificate});

                FileOutputStream keystoreOut = new FileOutputStream(keystoreFile);
                store.store(keystoreOut, keystorePassword.toCharArray());
                keystoreOut.flush();
                keystoreOut.close();
            } catch (Exception e) {
                throw new BuildException(e);
            }
        }
    }

    /**
     * Sets the type of key that will be generated. Defaults to DSA.
     * 
     * @param type type of key that will be generated
     */
    public void setKeyType(KeyType type) {
        keyType = type.getValue();
    }

    /**
     * Sets the size of the generated key. Defaults to 2048
     * 
     * @param size size of the generated key
     */
    public void setKeysize(int size) {
        keysize = size;
    }

    /**
     * Sets the number of years for which the certificate will be valid.
     * 
     * @param lifetime number of years for which the certificate will be valid
     */
    public void setCertificateLifetime(int lifetime) {
        certificateLifetime = lifetime;
    }

    /**
     * Sets the hostname that will appear in the certificate's DN.
     * 
     * @param name hostname that will appear in the certificate's DN
     */
    public void setHostName(String name) {
        hostname = name;
    }

    /**
     * Sets the file to which the private key will be written.
     * 
     * @param file file to which the private key will be written
     */
    public void setPrivateKeyFile(File file) {
        privateKeyFile = file;
    }

    /**
     * Sets the file to which the certificate will be written.
     * 
     * @param file file to which the certificate will be written
     */
    public void setCertificateFile(File file) {
        certificateFile = file;
    }

    /**
     * Sets the file to which the keystore will be written.
     * 
     * @param file file to which the keystore will be written
     */
    public void setKeystoreFile(File file) {
        keystoreFile = file;
    }

    /**
     * Sets the password for the generated keystore.
     * 
     * @param password password for the generated keystore
     */
    public void setKeystorePassword(String password) {
        keystorePassword = password;
    }

    /**
     * Sets the optional DNS subject alt names.
     * 
     * @param altNames space delimited set of subject alt names.
     */
    public void setDnsSubjectAltNames(String altNames) {
        dnsSubjectAltNames = altNames.split(" ");
    }

    /**
     * Sets the optional URI subject alt names.
     * 
     * @param altNames space delimited set of subject alt names.
     */
    public void setUriSubjectAltNames(String altNames) {
        uriSubjectAltNames = altNames.split(" ");
    }

    /** Validates the provided task input. */
    protected void validate() throws BuildException {
        if (keysize > 2048) {
            log("Key size is greater than 2048, this may cause problems with some JVMs", Project.MSG_WARN);
        }

        if (hostname == null || hostname.length() == 0) {
            throw new BuildException("The hostname attribute is required and may not contain an empty value");
        }

        if (keystoreFile != null && (keystorePassword == null || keystorePassword.length() == 0)) {
            throw new BuildException("Keystore password may not be null if a keystore file is given");
        }
    }

    /**
     * Generates the key pair for the certificate.
     * 
     * @return key pair for the certificate
     * 
     * @throws BuildException thrown if there is a problem generating the keys.
     */
    protected KeyPair generateKeyPair() throws BuildException {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(keyType);
            generator.initialize(keysize);
            return generator.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new BuildException("The " + keyType + " key type is not supported by this JVM");
        }
    }

    /**
     * Generates the self-signed certificate.
     * 
     * @param keypair keypair associated with the certificate
     * 
     * @return self-signed certificate
     * 
     * @throws BuildException thrown if the certificate can not be generated
     */
    protected X509Certificate generateCertificate(KeyPair keypair) throws BuildException {
        try {
            X509V3CertificateGenerator certifcateGenerator = new X509V3CertificateGenerator();
            certifcateGenerator.setPublicKey(keypair.getPublic());

            StringBuffer dnBuffer = new StringBuffer("CN=").append(hostname);

            X509Name dn = new X509Name(false, dnBuffer.toString(), new RdnConverter());
            certifcateGenerator.setIssuerDN(dn);
            certifcateGenerator.setSubjectDN(dn);

            GregorianCalendar date = new GregorianCalendar();
            certifcateGenerator.setNotBefore(date.getTime());

            date.set(GregorianCalendar.YEAR, date.get(GregorianCalendar.YEAR) + certificateLifetime);
            certifcateGenerator.setNotAfter(date.getTime());

            certifcateGenerator.setSerialNumber(new BigInteger(160, new SecureRandom()));

            certifcateGenerator.setSignatureAlgorithm("SHA1withRSA");

            certifcateGenerator.addExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(
                    new DERSequence(buildSubjectAltNames())));

            certifcateGenerator.addExtension(X509Extensions.SubjectKeyIdentifier, false,
                    new SubjectKeyIdentifierStructure(keypair.getPublic()));

            return certifcateGenerator.generate(keypair.getPrivate());
        } catch (Exception e) {
            log(e.toString(), Project.MSG_ERR);
            throw new BuildException("Unable to generate self-signed certificate", e);
        }
    }

    /**
     * Builds the subject alt names for the certificate.
     * 
     * @return subject alt names for the certificate
     */
    protected ASN1Encodable[] buildSubjectAltNames() {
        ArrayList<ASN1Encodable> subjectAltNames = new ArrayList<ASN1Encodable>();

        subjectAltNames.add(new GeneralName(GeneralName.dNSName, hostname));

        if (dnsSubjectAltNames != null) {
            for (String subjectAltName : dnsSubjectAltNames) {
                subjectAltNames.add(new GeneralName(GeneralName.dNSName, subjectAltName));
            }
        }

        if (uriSubjectAltNames != null) {
            for (String subjectAltName : uriSubjectAltNames) {
                subjectAltNames.add(new GeneralName(GeneralName.uniformResourceIdentifier, subjectAltName));
            }
        }

        return subjectAltNames.toArray(new ASN1Encodable[0]);
    }

    /** Key type enumeration. */
    public static class KeyType extends EnumeratedAttribute {

        public String[] getValues() {
            return new String[] {"DSA", "RSA"};
        }
    }
}
