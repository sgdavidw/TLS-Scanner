/**
 * TLS-Scanner - A TLS Configuration Analysistool based on TLS-Attacker
 *
 * Copyright 2014-2017 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner.report;

import de.rub.nds.tlsattacker.attacks.constants.DrownVulnerabilityType;
import de.rub.nds.tlsattacker.attacks.constants.EarlyCcsVulnerabilityType;
import de.rub.nds.tlsattacker.core.constants.CipherSuite;
import de.rub.nds.tlsattacker.core.constants.CompressionMethod;
import de.rub.nds.tlsattacker.core.constants.ExtensionType;
import de.rub.nds.tlsattacker.core.constants.NamedGroup;
import de.rub.nds.tlsattacker.core.constants.ProtocolVersion;
import de.rub.nds.tlsattacker.core.constants.SignatureAndHashAlgorithm;
import de.rub.nds.tlsattacker.core.constants.TokenBindingKeyParameters;
import de.rub.nds.tlsattacker.core.constants.TokenBindingVersion;
import de.rub.nds.tlsattacker.core.https.header.HttpsHeader;
import de.rub.nds.tlsscanner.constants.GcmPattern;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.probe.mac.CheckPattern;
import de.rub.nds.tlsscanner.probe.certificate.CertificateReport;
import de.rub.nds.tlsscanner.report.result.VersionSuiteListPair;
import de.rub.nds.tlsscanner.report.result.hpkp.HpkpPin;
import de.rub.nds.tlsscanner.report.result.paddingoracle.PaddingOracleTestResult;

import java.util.*;

import org.bouncycastle.crypto.tls.Certificate;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class SiteReport {

    //general
    private final List<ProbeType> probeTypeList;
    private List<PerformanceData> performanceList;

    private final String host;
    private Boolean serverIsAlive = null;
    private Boolean supportsSslTls = null;

    //Quirks
    private Boolean requiresSni = null;

    //common bugs
    private Map<String, Boolean> commonBugs = new HashMap<>();

    //Attacks
    private Boolean bleichenbacherVulnerable = null;
    private Boolean paddingOracleVulnerable = null;
    private List<PaddingOracleTestResult> paddingOracleTestResultList;
    private Boolean invalidCurveVulnerable = null;
    private Boolean invalidCurveEphermaralVulnerable = null;
    private Boolean poodleVulnerable = null;
    private Boolean tlsPoodleVulnerable = null;
    private Boolean cve20162107Vulnerable = null;
    private Boolean crimeVulnerable = null;
    private Boolean breachVulnerable = null;
    private Boolean sweet32Vulnerable = null;
    private DrownVulnerabilityType drownVulnerable = null;
    private Boolean logjamVulnerable = null;
    private Boolean heartbleedVulnerable = null;
    private EarlyCcsVulnerabilityType earlyCcsVulnerable = null;
    private Boolean freakVulnerable = null;

    //Version
    private List<ProtocolVersion> versions = null;
    private Map<String, Boolean> versionSupport = new HashMap<>();

    //Extensions
    private List<ExtensionType> supportedExtensions = null;
    private List<NamedGroup> supportedNamedGroups = null;
    private List<NamedGroup> supportedTls13Groups = null;
    private List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms = null;
    private List<TokenBindingVersion> supportedTokenBindingVersion = null;
    private List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters = null;
    private Boolean supportsExtendedMasterSecret = null;
    private Boolean supportsEncryptThenMacSecret = null;
    private Boolean supportsTokenbinding = null;

    //Compression
    private List<CompressionMethod> supportedCompressionMethods = null;

    //RFC
    private CheckPattern macCheckPatterAppData = null;
    private CheckPattern macCheckPatternFinished = null;
    private CheckPattern verifyCheckPattern = null;

    //Certificate
    private Certificate certificate = null;
    private List<CertificateReport> certificateReports = null;
    private Map<String, Boolean> certQualities = new HashMap<>();

    //Ciphers
    private List<VersionSuiteListPair> versionSuitePairs = null;
    private Set<CipherSuite> cipherSuites = null;
    private List<CipherSuite> supportedTls13CipherSuites = null;
    private Map<String, Boolean> cipherSupport = new HashMap<>();

    //Session
    private Boolean supportsSessionTicket = null;
    private Boolean supportsSessionIds = null;
    private Long sessionTicketLengthHint = null;
    private Boolean sessionTicketGetsRotated = null;
    private Boolean vulnerableTicketBleed = null;

    //Renegotiation + SCSV
    private Boolean supportsSecureRenegotiation = null;
    private Boolean supportsClientSideSecureRenegotiation = null;
    private Boolean supportsClientSideInsecureRenegotiation = null;
    private Boolean tlsFallbackSCSVsupported = null;

    //GCM Nonces
    private Boolean gcmReuse = null;
    private GcmPattern gcmPattern = null;
    private Boolean gcmCheck = null;

    //HTTPS Header
    private Boolean speaksHttps;
    private List<HttpsHeader> headerList = null;
    private Boolean supportsHsts = null;
    private Integer hstsMaxAge = null;
    private Boolean supportsHstsPreloading = null;
    private Boolean supportsHpkp = null;
    private Boolean supportsHpkpReportOnly = null;
    private Integer hpkpMaxAge = null;
    private List<HpkpPin> normalHpkpPins;
    private List<HpkpPin> reportOnlyHpkpPins;
    //NoColor Flag
    private boolean noColor = false;

    public SiteReport(String host, List<ProbeType> probeTypeList, boolean noColor) {
        this.host = host;
        this.probeTypeList = probeTypeList;
        this.noColor = noColor;
        performanceList = new LinkedList<>();
    }

    public String getHost() {
        return host;
    }

    public Boolean getRequiresSni() {
        return requiresSni;
    }

    public void setRequiresSni(Boolean requiresSni) {
        this.requiresSni = requiresSni;
    }

    public Boolean getCompressionIntolerance() {
        return this.commonBugs.get(CommonBugs.COMPRESSION_INTOLERANCE);
    }

    public void setCompressionIntolerance(Boolean compressionIntolerance) {
        this.commonBugs.put(CommonBugs.COMPRESSION_INTOLERANCE, compressionIntolerance);
    }

    public Boolean getCipherSuiteLengthIntolerance512() {
        return this.commonBugs.get(CommonBugs.CIPHER_SUITE_LENGTH_INTOLERANCE);
    }

    public void setCipherSuiteLengthIntolerance512(Boolean cipherSuiteLengthIntolerance512) {
        this.commonBugs.put(CommonBugs.CIPHER_SUITE_LENGTH_INTOLERANCE, cipherSuiteLengthIntolerance512);
    }

    public Boolean getAlpnIntolerance() {
        return this.commonBugs.get(CommonBugs.ALPN_INTOLERANCE);
    }

    public void setAlpnIntolerance(Boolean alpnIntolerance) {
        this.commonBugs.put(CommonBugs.ALPN_INTOLERANCE, alpnIntolerance);
    }

    public Boolean getClientHelloLengthIntolerance() {
        return this.commonBugs.get(CommonBugs.CLIENT_HELLO_LENGTH_INTOLERANCE);
    }

    public void setClientHelloLengthIntolerance(Boolean clientHelloLengthIntolerance) {
        this.commonBugs.put(CommonBugs.CLIENT_HELLO_LENGTH_INTOLERANCE, clientHelloLengthIntolerance);
    }

    public Boolean getEmptyLastExtensionIntolerance() {
        return this.commonBugs.get(CommonBugs.EMPTY_LAST_EXTENSION_INTOLERANCE);
    }

    public void setEmptyLastExtensionIntolerance(Boolean emptyLastExtensionIntolerance) {
        this.commonBugs.put(CommonBugs.EMPTY_LAST_EXTENSION_INTOLERANCE, emptyLastExtensionIntolerance);
    }

    public Boolean getOnlySecondCiphersuiteByteEvaluated() {
        return this.commonBugs.get(CommonBugs.ONLY_SECOND_CIPHERSUITE_BYTE_EVALUATED);
    }

    public void setOnlySecondCiphersuiteByteEvaluated(Boolean onlySecondCiphersuiteByteEvaluated) {
        this.commonBugs.put(CommonBugs.ONLY_SECOND_CIPHERSUITE_BYTE_EVALUATED, onlySecondCiphersuiteByteEvaluated);
    }

    public Boolean getNamedGroupIntolerant() {
        return this.commonBugs.get(CommonBugs.NAMED_GROUP_INTOLERANT);
    }

    public void setNamedGroupIntolerant(Boolean namedGroupIntolerant) {
        this.commonBugs.put(CommonBugs.NAMED_GROUP_INTOLERANT, namedGroupIntolerant);
    }

    public Boolean getNamedSignatureAndHashAlgorithmIntolerance() {
        return this.commonBugs.get(CommonBugs.NAMED_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE);
    }

    public void setNamedSignatureAndHashAlgorithmIntolerance(Boolean namedSignatureAndHashAlgorithmIntolerance) {
        this.commonBugs.put(CommonBugs.NAMED_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE, namedSignatureAndHashAlgorithmIntolerance);
    }

    public Boolean getIgnoresCipherSuiteOffering() {
        return this.commonBugs.get(CommonBugs.IGNORES_CIPHER_SUITE_OFFERING);
    }

    public void setIgnoresCipherSuiteOffering(Boolean ignoresCipherSuiteOffering) {
        this.commonBugs.put(CommonBugs.IGNORES_CIPHER_SUITE_OFFERING, ignoresCipherSuiteOffering);
    }

    public Boolean getReflectsCipherSuiteOffering() {
        return this.commonBugs.get(CommonBugs.REFLECTS_CIPHER_SUITE_OFFERING);
    }

    public void setReflectsCipherSuiteOffering(Boolean reflectsCipherSuiteOffering) {
        this.commonBugs.put(CommonBugs.REFLECTS_CIPHER_SUITE_OFFERING, reflectsCipherSuiteOffering);
    }

    public Boolean getIgnoresOfferedNamedGroups() {
        return this.commonBugs.get(CommonBugs.IGNORES_OFFERED_NAMED_GROUPS);
    }

    public void setIgnoresOfferedNamedGroups(Boolean ignoresOfferedNamedGroups) {
        this.commonBugs.put(CommonBugs.IGNORES_OFFERED_NAMED_GROUPS, ignoresOfferedNamedGroups);
    }

    public Boolean getIgnoresOfferedSignatureAndHashAlgorithms() {
        return this.commonBugs.get(CommonBugs.IGNORES_OFFERED_SIGNATURE_AND_HASH_ALGORITHMS);
    }

    public void setIgnoresOfferedSignatureAndHashAlgorithms(Boolean ignoresOfferedSignatureAndHashAlgorithms) {
        this.commonBugs.put(CommonBugs.IGNORES_OFFERED_SIGNATURE_AND_HASH_ALGORITHMS, ignoresOfferedSignatureAndHashAlgorithms);
    }

    public Boolean getMaxLengthClientHelloIntolerant() {
        return this.commonBugs.get(CommonBugs.MAX_LENGTH_CLIENT_HELLO_INTOLERANT);
    }

    public void setMaxLengthClientHelloIntolerant(Boolean maxLengthClientHelloIntolerant) {
        this.commonBugs.put(CommonBugs.MAX_LENGTH_CLIENT_HELLO_INTOLERANT, maxLengthClientHelloIntolerant);
    }

    public Boolean getFreakVulnerable() {
        return freakVulnerable;
    }

    public void setFreakVulnerable(Boolean freakVulnerable) {
        this.freakVulnerable = freakVulnerable;
    }

    public Boolean getHeartbleedVulnerable() {
        return heartbleedVulnerable;
    }

    public void setHeartbleedVulnerable(Boolean heartbleedVulnerable) {
        this.heartbleedVulnerable = heartbleedVulnerable;
    }

    public EarlyCcsVulnerabilityType getEarlyCcsVulnerable() {
        return earlyCcsVulnerable;
    }

    public void setEarlyCcsVulnerable(EarlyCcsVulnerabilityType earlyCcsVulnerable) {
        this.earlyCcsVulnerable = earlyCcsVulnerable;
    }

    public Boolean getServerIsAlive() {
        return serverIsAlive;
    }

    public void setServerIsAlive(Boolean serverIsAlive) {
        this.serverIsAlive = serverIsAlive;
    }

    public Boolean getSupportsSsl2() {
        return this.versionSupport.get(VersionSupport.SSL_2);
    }

    public void setSupportsSsl2(Boolean supportsSsl2) {
       this.versionSupport.put(VersionSupport.SSL_2, supportsSsl2);
    }

    public Boolean getSupportsSsl3() {
        return this.versionSupport.get(VersionSupport.SSL_3);
    }

    public void setSupportsSsl3(Boolean supportsSsl3) {
        this.versionSupport.put(VersionSupport.SSL_3, supportsSsl3);
    }

    public Boolean getSupportsTls10() {
        return this.versionSupport.get(VersionSupport.TLS_10);
    }

    public void setSupportsTls10(Boolean supportsTls10) {
        this.versionSupport.put(VersionSupport.TLS_10, supportsTls10);
    }

    public Boolean getSupportsTls11() {
        return this.versionSupport.get(VersionSupport.TLS_11);
    }

    public void setSupportsTls11(Boolean supportsTls11) {
        this.versionSupport.put(VersionSupport.TLS_11, supportsTls11);
    }

    public Boolean getSupportsTls12() {
        return this.versionSupport.get(VersionSupport.TLS_12);
    }

    public void setSupportsTls12(Boolean supportsTls12) {
        this.versionSupport.put(VersionSupport.TLS_12, supportsTls12);
    }

    public Boolean supportsAnyTls13() {
        return this.versionSupport.get(VersionSupport.TLS_13) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_14) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_15) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_16) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_17) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_18) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_19) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_20) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_21) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_22) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_23) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_24) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_25) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_26) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_27) == Boolean.TRUE
                || this.versionSupport.get(VersionSupport.TLS_13_DRAFT_28) == Boolean.TRUE;
    }

    public Boolean getSupportsTls13() {
        return this.versionSupport.get(VersionSupport.TLS_13);
    }

    public void setSupportsTls13(Boolean supportsTls13) {
        this.versionSupport.put(VersionSupport.TLS_13, supportsTls13);
    }

    public Boolean getSupportsTls13Draft14() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_14);
    }

    public void setSupportsTls13Draft14(Boolean supportsTls13Draft14) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_14, supportsTls13Draft14);
    }

    public Boolean getSupportsTls13Draft15() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_15);
    }

    public void setSupportsTls13Draft15(Boolean supportsTls13Draft15) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_15, supportsTls13Draft15);
    }

    public Boolean getSupportsTls13Draft16() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_16);
    }

    public void setSupportsTls13Draft16(Boolean supportsTls13Draft16) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_16, supportsTls13Draft16);
    }

    public Boolean getSupportsTls13Draft17() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_17);
    }

    public void setSupportsTls13Draft17(Boolean supportsTls13Draft17) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_17, supportsTls13Draft17);
    }

    public Boolean getSupportsTls13Draft18() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_18);
    }

    public void setSupportsTls13Draft18(Boolean supportsTls13Draft18) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_18, supportsTls13Draft18);
    }

    public Boolean getSupportsTls13Draft19() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_19);
    }

    public void setSupportsTls13Draft19(Boolean supportsTls13Draft19) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_19, supportsTls13Draft19);
    }

    public Boolean getSupportsTls13Draft20() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_20);
    }

    public void setSupportsTls13Draft20(Boolean supportsTls13Draft20) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_20, supportsTls13Draft20);
    }

    public Boolean getSupportsTls13Draft21() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_21);
    }

    public void setSupportsTls13Draft21(Boolean supportsTls13Draft21) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_21, supportsTls13Draft21);
    }

    public Boolean getSupportsTls13Draft22() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_22);
    }

    public void setSupportsTls13Draft22(Boolean supportsTls13Draft22) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_22, supportsTls13Draft22);
    }

    public Boolean getSupportsTls13Draft23() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_23);
    }

    public void setSupportsTls13Draft23(Boolean supportsTls13Draft23) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_23, supportsTls13Draft23);
    }

    public Boolean getSupportsTls13Draft24() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_24);
    }

    public void setSupportsTls13Draft24(Boolean supportsTls13Draft24) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_24, supportsTls13Draft24);
    }

    public Boolean getSupportsTls13Draft25() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_25);
    }

    public void setSupportsTls13Draft25(Boolean supportsTls13Draft25) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_25, supportsTls13Draft25);
    }

    public Boolean getSupportsTls13Draft26() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_26);
    }

    public void setSupportsTls13Draft26(Boolean supportsTls13Draft26) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_26, supportsTls13Draft26);
    }

    public Boolean getSupportsTls13Draft27() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_27);
    }

    public void setSupportsTls13Draft27(Boolean supportsTls13Draft27) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_27, supportsTls13Draft27);
    }

    public Boolean getSupportsTls13Draft28() {
        return this.versionSupport.get(VersionSupport.TLS_13_DRAFT_28);
    }

    public void setSupportsTls13Draft28(Boolean supportsTls13Draft28) {
        this.versionSupport.put(VersionSupport.TLS_13_DRAFT_28, supportsTls13Draft28);
    }

    public Boolean getSupportsDtls10() {
        return this.versionSupport.get(VersionSupport.DTLS_10);
    }

    public void setSupportsDtls10(Boolean supportsDtls10) {
        this.versionSupport.put(VersionSupport.DTLS_10, supportsDtls10);
    }

    public Boolean getSupportsDtls12() {
        return this.versionSupport.get(VersionSupport.DTLS_12);
    }

    public void setSupportsDtls12(Boolean supportsDtls12) {
        this.versionSupport.put(VersionSupport.DTLS_12, supportsDtls12);
    }

    public Boolean getSupportsDtls13() {
        return this.versionSupport.get(VersionSupport.DTLS_13);
    }

    public void setSupportsDtls13(Boolean supportsDtls13) {
        this.versionSupport.put(VersionSupport.DTLS_13, supportsDtls13);
    }

    public List<TokenBindingVersion> getSupportedTokenBindingVersion() {
        return supportedTokenBindingVersion;
    }

    public void setSupportedTokenBindingVersion(List<TokenBindingVersion> supportedTokenBindingVersion) {
        this.supportedTokenBindingVersion = supportedTokenBindingVersion;
    }

    public List<TokenBindingKeyParameters> getSupportedTokenBindingKeyParameters() {
        return supportedTokenBindingKeyParameters;
    }

    public void setSupportedTokenBindingKeyParameters(List<TokenBindingKeyParameters> supportedTokenBindingKeyParameters) {
        this.supportedTokenBindingKeyParameters = supportedTokenBindingKeyParameters;
    }

    public List<CertificateReport> getCertificateReports() {
        return certificateReports;
    }

    public void setCertificateReports(List<CertificateReport> certificateReports) {
        this.certificateReports = certificateReports;
    }

    public Boolean getSupportsAes() {
        return this.cipherSupport.get(CipherSupport.AES);
    }

    public void setSupportsAes(Boolean supportsAes) {
        this.cipherSupport.put(CipherSupport.AES, supportsAes);
    }

    public Boolean getSupportsCamellia() {
        return this.cipherSupport.get(CipherSupport.CAMELLIA);
    }

    public void setSupportsCamellia(Boolean supportsCamellia) {
        this.cipherSupport.put(CipherSupport.CAMELLIA, supportsCamellia);
    }

    public Boolean getSupportsAria() {
        return this.cipherSupport.get(CipherSupport.ARIA);
    }

    public void setSupportsAria(Boolean supportsAria) {
        this.cipherSupport.put(CipherSupport.ARIA, supportsAria);
    }

    public Boolean getSupportsChacha() {
        return this.cipherSupport.get(CipherSupport.CHACHA);
    }

    public void setSupportsChacha(Boolean supportsChacha) {
        this.cipherSupport.put(CipherSupport.CHACHA, supportsChacha);
    }

    public Boolean getSupportsRsa() {
        return this.cipherSupport.get(CipherSupport.RSA);
    }

    public void setSupportsRsa(Boolean supportsRsa) {
        this.cipherSupport.put(CipherSupport.RSA, supportsRsa);
    }

    public Boolean getSupportsDh() {
        return this.cipherSupport.get(CipherSupport.DH);
    }

    public void setSupportsDh(Boolean supportsDh) {
        this.cipherSupport.put(CipherSupport.DH, supportsDh);
    }

    public Boolean getSupportsEcdh() {
        return this.cipherSupport.get(CipherSupport.ECDH);
    }

    public void setSupportsEcdh(Boolean supportsEcdh) {
        this.cipherSupport.put(CipherSupport.ECDH, supportsEcdh);
    }

    public Boolean getSupportsGost() {
        return this.cipherSupport.get(CipherSupport.GOST);
    }

    public void setSupportsGost(Boolean supportsGost) {
        this.cipherSupport.put(CipherSupport.GOST, supportsGost);
    }

    public Boolean getSupportsSrp() {
        return this.cipherSupport.get(CipherSupport.SRP);
    }

    public void setSupportsSrp(Boolean supportsSrp) {
        this.cipherSupport.put(CipherSupport.SRP, supportsSrp);
    }

    public Boolean getSupportsKerberos() {
        return this.cipherSupport.get(CipherSupport.KERBEROS);
    }

    public void setSupportsKerberos(Boolean supportsKerberos) {
        this.cipherSupport.put(CipherSupport.KERBEROS, supportsKerberos);
    }

    public Boolean getSupportsPskPlain() {
        return this.cipherSupport.get(CipherSupport.PSK_PLAIN);
    }

    public void setSupportsPskPlain(Boolean supportsPskPlain) {
        this.cipherSupport.put(CipherSupport.PSK_PLAIN, supportsPskPlain);
    }

    public Boolean getSupportsPskRsa() {
        return this.cipherSupport.get(CipherSupport.PSK_RSA);
    }

    public void setSupportsPskRsa(Boolean supportsPskRsa) {
        this.cipherSupport.put(CipherSupport.PSK_RSA, supportsPskRsa);
    }

    public Boolean getSupportsPskDhe() {
        return this.cipherSupport.get(CipherSupport.PSK_DHE);
    }

    public void setSupportsPskDhe(Boolean supportsPskDhe) {
        this.cipherSupport.put(CipherSupport.PSK_DHE, supportsPskDhe);
    }

    public Boolean getSupportsPskEcdhe() {
        return this.cipherSupport.get(CipherSupport.PSK_ECDHE);
    }

    public void setSupportsPskEcdhe(Boolean supportsPskEcdhe) {
        this.cipherSupport.put(CipherSupport.PSK_ECDHE, supportsPskEcdhe);
    }

    public Boolean getSupportsFortezza() {
        return this.cipherSupport.get(CipherSupport.FORTEZZA);
    }

    public void setSupportsFortezza(Boolean supportsFortezza) {
        this.cipherSupport.put(CipherSupport.FORTEZZA, supportsFortezza);
    }

    public Boolean getSupportsNewHope() {
        return this.cipherSupport.get(CipherSupport.NEW_HOPE);
    }

    public void setSupportsNewHope(Boolean supportsNewHope) {
        this.cipherSupport.put(CipherSupport.NEW_HOPE, supportsNewHope);
    }

    public Boolean getSupportsEcmqv() {
        return this.cipherSupport.get(CipherSupport.ECMQV);
    }

    public void setSupportsEcmqv(Boolean supportsEcmqv) {
        this.cipherSupport.put(CipherSupport.ECMQV, supportsEcmqv);
    }

    public Boolean getPrefersPfsCiphers() {
        return this.cipherSupport.get(CipherSupport.PREFERS_PFS_CIPHERS);
    }

    public void setPrefersPfsCiphers(Boolean prefersPfsCiphers) {
        this.cipherSupport.put(CipherSupport.PREFERS_PFS_CIPHERS, prefersPfsCiphers);
    }

    public Boolean getSupportsStreamCiphers() {
        return this.cipherSupport.get(CipherSupport.STREAM_CIPHERS);
    }

    public void setSupportsStreamCiphers(Boolean supportsStreamCiphers) {
        this.cipherSupport.put(CipherSupport.STREAM_CIPHERS, supportsStreamCiphers);
    }

    public Boolean getSupportsBlockCiphers() {
        return this.cipherSupport.get(CipherSupport.BLOCK_CIPHERS);
    }

    public void setSupportsBlockCiphers(Boolean supportsBlockCiphers) {
        this.cipherSupport.put(CipherSupport.BLOCK_CIPHERS, supportsBlockCiphers);
    }

    public Boolean getGcmCheck() {
        return gcmCheck;
    }

    public void setGcmCheck(Boolean gcmCheck) {
        this.gcmCheck = gcmCheck;
    }

    public List<ProtocolVersion> getVersions() {
        return versions;
    }

    public void setVersions(List<ProtocolVersion> versions) {
        this.versions = versions;
    }

    public Set<CipherSuite> getCipherSuites() {
        return cipherSuites;
    }

    public void setCipherSuites(Set<CipherSuite> cipherSuites) {
        this.cipherSuites = cipherSuites;
    }

    public List<CipherSuite> getSupportedTls13CipherSuites() {
        return supportedTls13CipherSuites;
    }

    public void setSupportedTls13CipherSuites(List<CipherSuite> supportedTls13CipherSuites) {
        this.supportedTls13CipherSuites = supportedTls13CipherSuites;
    }

    public Certificate getCertificate() {
        return certificate;
    }

    public void setCertificate(Certificate certificate) {
        this.certificate = certificate;
    }

    public Boolean getBleichenbacherVulnerable() {
        return bleichenbacherVulnerable;
    }

    public void setBleichenbacherVulnerable(Boolean bleichenbacherVulnerable) {
        this.bleichenbacherVulnerable = bleichenbacherVulnerable;
    }

    public Boolean getPaddingOracleVulnerable() {
        return paddingOracleVulnerable;
    }

    public void setPaddingOracleVulnerable(Boolean paddingOracleVulnerable) {
        this.paddingOracleVulnerable = paddingOracleVulnerable;
    }

    public Boolean getInvalidCurveVulnerable() {
        return invalidCurveVulnerable;
    }

    public void setInvalidCurveVulnerable(Boolean invalidCurveVulnerable) {
        this.invalidCurveVulnerable = invalidCurveVulnerable;
    }

    public Boolean getInvalidCurveEphermaralVulnerable() {
        return invalidCurveEphermaralVulnerable;
    }

    public void setInvalidCurveEphermaralVulnerable(Boolean invalidCurveEphermaralVulnerable) {
        this.invalidCurveEphermaralVulnerable = invalidCurveEphermaralVulnerable;
    }

    public Boolean getPoodleVulnerable() {
        return poodleVulnerable;
    }

    public void setPoodleVulnerable(Boolean poodleVulnerable) {
        this.poodleVulnerable = poodleVulnerable;
    }

    public Boolean getTlsPoodleVulnerable() {
        return tlsPoodleVulnerable;
    }

    public void setTlsPoodleVulnerable(Boolean tlsPoodleVulnerable) {
        this.tlsPoodleVulnerable = tlsPoodleVulnerable;
    }

    public Boolean getCve20162107Vulnerable() {
        return cve20162107Vulnerable;
    }

    public void setCve20162107Vulnerable(Boolean cve20162107Vulnerable) {
        this.cve20162107Vulnerable = cve20162107Vulnerable;
    }

    public Boolean getCrimeVulnerable() {
        return crimeVulnerable;
    }

    public void setCrimeVulnerable(Boolean crimeVulnerable) {
        this.crimeVulnerable = crimeVulnerable;
    }

    public Boolean getBreachVulnerable() {
        return breachVulnerable;
    }

    public void setBreachVulnerable(Boolean breachVulnerable) {
        this.breachVulnerable = breachVulnerable;
    }

    public Boolean getEnforcesCipherSuiteOrdering() {
        return this.cipherSupport.get(CipherSupport.ENFORCES_CIPHER_SUITE_ORDERING);
    }

    public void setEnforcesCipherSuiteOrdering(Boolean enforcesCipherSuiteOrdering) {
        this.cipherSupport.put(CipherSupport.ENFORCES_CIPHER_SUITE_ORDERING, enforcesCipherSuiteOrdering);
    }

    public List<NamedGroup> getSupportedNamedGroups() {
        return supportedNamedGroups;
    }

    public void setSupportedNamedGroups(List<NamedGroup> supportedNamedGroups) {
        this.supportedNamedGroups = supportedNamedGroups;
    }

    public List<NamedGroup> getSupportedTls13Groups() {
        return supportedTls13Groups;
    }

    public void setSupportedTls13Groups(List<NamedGroup> supportedTls13Groups) {
        this.supportedTls13Groups = supportedTls13Groups;
    }

    public List<SignatureAndHashAlgorithm> getSupportedSignatureAndHashAlgorithms() {
        return supportedSignatureAndHashAlgorithms;
    }

    public void setSupportedSignatureAndHashAlgorithms(List<SignatureAndHashAlgorithm> supportedSignatureAndHashAlgorithms) {
        this.supportedSignatureAndHashAlgorithms = supportedSignatureAndHashAlgorithms;
    }

    public List<ExtensionType> getSupportedExtensions() {
        return supportedExtensions;
    }

    public void setSupportedExtensions(List<ExtensionType> supportedExtensions) {
        this.supportedExtensions = supportedExtensions;
    }

    public List<CompressionMethod> getSupportedCompressionMethods() {
        return supportedCompressionMethods;
    }

    public void setSupportedCompressionMethods(List<CompressionMethod> supportedCompressionMethods) {
        this.supportedCompressionMethods = supportedCompressionMethods;
    }

    public CheckPattern getMacCheckPatternAppData() {
        return macCheckPatterAppData;
    }

    public void setMacCheckPatterAppData(CheckPattern macCheckPatterAppData) {
        this.macCheckPatterAppData = macCheckPatterAppData;
    }

    public CheckPattern getVerifyCheckPattern() {
        return verifyCheckPattern;
    }

    public void setVerifyCheckPattern(CheckPattern verifyCheckPattern) {
        this.verifyCheckPattern = verifyCheckPattern;
    }

    public Boolean getSupportsExtendedMasterSecret() {
        return supportsExtendedMasterSecret;
    }

    public void setSupportsExtendedMasterSecret(Boolean supportsExtendedMasterSecret) {
        this.supportsExtendedMasterSecret = supportsExtendedMasterSecret;
    }

    public Boolean getSupportsEncryptThenMacSecret() {
        return supportsEncryptThenMacSecret;
    }

    public void setSupportsEncryptThenMacSecret(Boolean supportsEncryptThenMacSecret) {
        this.supportsEncryptThenMacSecret = supportsEncryptThenMacSecret;
    }

    public Boolean getSupportsTokenbinding() {
        return supportsTokenbinding;
    }

    public void setSupportsTokenbinding(Boolean supportsTokenbinding) {
        this.supportsTokenbinding = supportsTokenbinding;
    }

    public Boolean getSupportsSslTls() {
        return supportsSslTls;
    }

    public void setSupportsSslTls(Boolean supportsSslTls) {
        this.supportsSslTls = supportsSslTls;
    }

    public Boolean getCertificateExpired() {
        return this.certQualities.get(CertificateQualities.EXPIRED);
    }

    public void setCertificateExpired(Boolean certificateExpired) {
        this.certQualities.put(CertificateQualities.EXPIRED, certificateExpired);
    }

    public Boolean getCertificateNotYetValid() {
        return this.certQualities.get(CertificateQualities.NOT_YET_VALID);
    }

    public void setCertificateNotYetValid(Boolean certificateNotYetValid) {
        this.certQualities.put(CertificateQualities.NOT_YET_VALID, certificateNotYetValid);
    }

    public Boolean getCertificateHasWeakHashAlgorithm() {
        return this.certQualities.get(CertificateQualities.WEAK_HASH_ALGORITHM);
    }

    public void setCertificateHasWeakHashAlgorithm(Boolean certificateHasWeakHashAlgorithm) {
        this.certQualities.put(CertificateQualities.WEAK_HASH_ALGORITHM, certificateHasWeakHashAlgorithm);
    }

    public Boolean getCertificateHasWeakSignAlgorithm() {
        return this.certQualities.get(CertificateQualities.WEAK_SIGN_ALGORITHM);
    }

    public void setCertificateHasWeakSignAlgorithm(Boolean certificateHasWeakSignAlgorithm) {
        this.certQualities.put(CertificateQualities.WEAK_SIGN_ALGORITHM, certificateHasWeakSignAlgorithm);
    }

    public Boolean getCertificateMachtesDomainName() {
        return this.certQualities.get(CertificateQualities.MATCHES_DOMAIN_NAME);
    }

    public void setCertificateMachtesDomainName(Boolean certificateMachtesDomainName) {
        this.certQualities.put(CertificateQualities.MATCHES_DOMAIN_NAME, certificateMachtesDomainName);
    }

    public Boolean getCertificateIsTrusted() {
        return this.certQualities.get(CertificateQualities.IS_TRUSTED);
    }

    public void setCertificateIsTrusted(Boolean certificateIsTrusted) {
        this.certQualities.put(CertificateQualities.IS_TRUSTED, certificateIsTrusted);
    }

    public Boolean getCertificateKeyIsBlacklisted() {
        return this.certQualities.get(CertificateQualities.KEY_IS_BLACKLISTED);
    }

    public void setCertificateKeyIsBlacklisted(Boolean certificateKeyIsBlacklisted) {
        this.certQualities.put(CertificateQualities.KEY_IS_BLACKLISTED, certificateKeyIsBlacklisted);
    }

    public Boolean getSupportsNullCiphers() {
        return this.cipherSupport.get(CipherSupport.NULL_CIPHERS);
    }

    public void setSupportsNullCiphers(Boolean supportsNullCiphers) {
        this.cipherSupport.put(CipherSupport.NULL_CIPHERS, supportsNullCiphers);
    }

    public Boolean getSupportsAnonCiphers() {
        return this.cipherSupport.get(CipherSupport.ANON_CIPHERS);
    }

    public void setSupportsAnonCiphers(Boolean supportsAnonCiphers) {
        this.cipherSupport.put(CipherSupport.ANON_CIPHERS, supportsAnonCiphers);
    }

    public Boolean getSupportsExportCiphers() {
        return this.cipherSupport.get(CipherSupport.EXPORT_CIPHERS);
    }

    public void setSupportsExportCiphers(Boolean supportsExportCiphers) {
        this.cipherSupport.put(CipherSupport.EXPORT_CIPHERS, supportsExportCiphers);
    }

    public Boolean getSupportsDesCiphers() {
        return this.cipherSupport.get(CipherSupport.DES_CIPHERS);
    }

    public void setSupportsDesCiphers(Boolean supportsDesCiphers) {
        this.cipherSupport.put(CipherSupport.DES_CIPHERS, supportsDesCiphers);
    }

    public Boolean getSupportsSeedCiphers() {
        return this.cipherSupport.get(CipherSupport.SEED_CIPHERS);
    }

    public void setSupportsSeedCiphers(Boolean supportsSeedCiphers) {
        this.cipherSupport.put(CipherSupport.SEED_CIPHERS, supportsSeedCiphers);
    }

    public Boolean getSupportsIdeaCiphers() {
        return this.cipherSupport.get(CipherSupport.IDEA_CIPHERS);
    }

    public void setSupportsIdeaCiphers(Boolean supportsIdeaCiphers) {
        this.cipherSupport.put(CipherSupport.IDEA_CIPHERS, supportsIdeaCiphers);
    }

    public Boolean getSupportsRc2Ciphers() {
        return this.cipherSupport.get(CipherSupport.RC2_CIPHERS);
    }

    public void setSupportsRc2Ciphers(Boolean supportsRc2Ciphers) {
        this.cipherSupport.put(CipherSupport.RC2_CIPHERS, supportsRc2Ciphers);
    }

    public Boolean getSupportsRc4Ciphers() {
        return this.cipherSupport.get(CipherSupport.RC4_CIPHERS);
    }

    public void setSupportsRc4Ciphers(Boolean supportsRc4Ciphers) {
        this.cipherSupport.put(CipherSupport.RC4_CIPHERS, supportsRc4Ciphers);
    }

    public Boolean getSupportsTrippleDesCiphers() {
        return this.cipherSupport.get(CipherSupport.TRIPLE_DES_CIPHERS);
    }

    public void setSupportsTrippleDesCiphers(Boolean supportsTrippleDesCiphers) {
        this.cipherSupport.put(CipherSupport.TRIPLE_DES_CIPHERS, supportsTrippleDesCiphers);
    }

    public Boolean getSupportsPostQuantumCiphers() {
        return this.cipherSupport.get(CipherSupport.POST_QUANTUM_CIPHERS);
    }

    public void setSupportsPostQuantumCiphers(Boolean supportsPostQuantumCiphers) {
        this.cipherSupport.put(CipherSupport.POST_QUANTUM_CIPHERS, supportsPostQuantumCiphers);
    }

    public Boolean getSupportsAeadCiphers() {
        return this.cipherSupport.get(CipherSupport.AEAD_CIPHERS);
    }

    public void setSupportsAeadCiphers(Boolean supportsAeadCiphers) {
        this.cipherSupport.put(CipherSupport.AEAD_CIPHERS, supportsAeadCiphers);
    }

    public Boolean getSupportsPfsCiphers() {
        return this.cipherSupport.get(CipherSupport.PFS_CIPHERS);
    }

    public void setSupportsPfsCiphers(Boolean supportsPfsCiphers) {
        this.cipherSupport.put(CipherSupport.PFS_CIPHERS, supportsPfsCiphers);
    }

    public Boolean getSupportsOnlyPfsCiphers() {
        return this.cipherSupport.get(CipherSupport.ONLY_PFS_CIPHERS);
    }

    public void setSupportsOnlyPfsCiphers(Boolean supportsOnlyPfsCiphers) {
        this.cipherSupport.put(CipherSupport.ONLY_PFS_CIPHERS, supportsOnlyPfsCiphers);
    }

    public Boolean getSupportsSessionTicket() {
        return supportsSessionTicket;
    }

    public void setSupportsSessionTicket(Boolean supportsSessionTicket) {
        this.supportsSessionTicket = supportsSessionTicket;
    }

    public Boolean getSupportsSessionIds() {
        return supportsSessionIds;
    }

    public void setSupportsSessionIds(Boolean supportsSessionIds) {
        this.supportsSessionIds = supportsSessionIds;
    }

    public Long getSessionTicketLengthHint() {
        return sessionTicketLengthHint;
    }

    public void setSessionTicketLengthHint(Long sessionTicketLengthHint) {
        this.sessionTicketLengthHint = sessionTicketLengthHint;
    }

    public Boolean getSessionTicketGetsRotated() {
        return sessionTicketGetsRotated;
    }

    public void setSessionTicketGetsRotated(Boolean sessionTicketGetsRotated) {
        this.sessionTicketGetsRotated = sessionTicketGetsRotated;
    }

    public Boolean getVulnerableTicketBleed() {
        return vulnerableTicketBleed;
    }

    public void setVulnerableTicketBleed(Boolean vulnerableTicketBleed) {
        this.vulnerableTicketBleed = vulnerableTicketBleed;
    }

    public Boolean getSupportsSecureRenegotiation() {
        return supportsSecureRenegotiation;
    }

    public void setSupportsSecureRenegotiation(Boolean supportsSecureRenegotiation) {
        this.supportsSecureRenegotiation = supportsSecureRenegotiation;
    }

    public Boolean getSupportsClientSideSecureRenegotiation() {
        return supportsClientSideSecureRenegotiation;
    }

    public void setSupportsClientSideSecureRenegotiation(Boolean supportsClientSideSecureRenegotiation) {
        this.supportsClientSideSecureRenegotiation = supportsClientSideSecureRenegotiation;
    }

    public Boolean getSupportsClientSideInsecureRenegotiation() {
        return supportsClientSideInsecureRenegotiation;
    }

    public void setSupportsClientSideInsecureRenegotiation(Boolean supportsClientSideInsecureRenegotiation) {
        this.supportsClientSideInsecureRenegotiation = supportsClientSideInsecureRenegotiation;
    }

    public Boolean getTlsFallbackSCSVsupported() {
        return tlsFallbackSCSVsupported;
    }

    public void setTlsFallbackSCSVsupported(Boolean tlsFallbackSCSVsupported) {
        this.tlsFallbackSCSVsupported = tlsFallbackSCSVsupported;
    }

    public Boolean getSweet32Vulnerable() {
        return sweet32Vulnerable;
    }

    public void setSweet32Vulnerable(Boolean sweet32Vulnerable) {
        this.sweet32Vulnerable = sweet32Vulnerable;
    }

    public DrownVulnerabilityType getDrownVulnerable() {
        return drownVulnerable;
    }

    public void setDrownVulnerable(DrownVulnerabilityType drownVulnerable) {
        this.drownVulnerable = drownVulnerable;
    }

    public Boolean getLogjamVulnerable() {
        return logjamVulnerable;
    }

    public void setLogjamVulnerable(Boolean logjamVulnerable) {
        this.logjamVulnerable = logjamVulnerable;
    }

    public Boolean getVersionIntolerance() {
        return this.commonBugs.get(CommonBugs.VERSION_INTOLERANCE);
    }

    public void setVersionIntolerance(Boolean versionIntolerance) {
        this.commonBugs.put(CommonBugs.VERSION_INTOLERANCE, versionIntolerance);
    }

    public Boolean getExtensionIntolerance() {
        return this.commonBugs.get(CommonBugs.EXTENSION_INTOLERANCE);
    }

    public void setExtensionIntolerance(Boolean extensionIntolerance) {
        this.commonBugs.put(CommonBugs.EXTENSION_INTOLERANCE, extensionIntolerance);
    }

    public Boolean getCipherSuiteIntolerance() {
        return this.commonBugs.get(CommonBugs.CIPHER_SUITE_INTOLERANCE);
    }

    public void setCipherSuiteIntolerance(Boolean cipherSuiteIntolerance) {
        this.commonBugs.put(CommonBugs.CIPHER_SUITE_INTOLERANCE, cipherSuiteIntolerance);
    }

    public Boolean getGcmReuse() {
        return gcmReuse;
    }

    public void setGcmReuse(Boolean gcmReuse) {
        this.gcmReuse = gcmReuse;
    }

    public GcmPattern getGcmPattern() {
        return gcmPattern;
    }

    public void setGcmPattern(GcmPattern gcmPattern) {
        this.gcmPattern = gcmPattern;
    }

    public List<VersionSuiteListPair> getVersionSuitePairs() {
        return versionSuitePairs;
    }

    public void setVersionSuitePairs(List<VersionSuiteListPair> versionSuitePairs) {
        this.versionSuitePairs = versionSuitePairs;
    }

    public Boolean getSupportsStaticEcdh() {
        return this.cipherSupport.get(CipherSupport.STATIC_ECDH);
    }

    public void setSupportsStaticEcdh(Boolean supportsStaticEcdh) {
        this.cipherSupport.put(CipherSupport.STATIC_ECDH, supportsStaticEcdh);
    }

    public boolean isNoColour() {
        return noColor;
    }

    public String getFullReport(ScannerDetail detail) {
        return new SiteReportPrinter(this, detail).getFullReport();
    }

    @Override
    public String toString() {
        return getFullReport(ScannerDetail.NORMAL);
    }

    public List<ProbeType> getProbeTypeList() {
        return probeTypeList;
    }

    public CheckPattern getMacCheckPatternFinished() {
        return macCheckPatternFinished;
    }

    public void setMacCheckPatternFinished(CheckPattern macCheckPatternFinished) {
        this.macCheckPatternFinished = macCheckPatternFinished;
    }

    public List<PerformanceData> getPerformanceList() {
        return performanceList;
    }

    public void setPerformanceList(List<PerformanceData> performanceList) {
        this.performanceList = performanceList;
    }

    public List<PaddingOracleTestResult> getPaddingOracleTestResultList() {
        return paddingOracleTestResultList;
    }

    public void setPaddingOracleTestResultList(List<PaddingOracleTestResult> paddingOracleTestResultList) {
        this.paddingOracleTestResultList = paddingOracleTestResultList;
    }

    public List<HttpsHeader> getHeaderList() {
        return headerList;
    }

    public void setHeaderList(List<HttpsHeader> headerList) {
        this.headerList = headerList;
    }

    public Boolean getSupportsHsts() {
        return supportsHsts;
    }

    public void setSupportsHsts(Boolean supportsHsts) {
        this.supportsHsts = supportsHsts;
    }

    public Boolean getSupportsHstsPreloading() {
        return supportsHstsPreloading;
    }

    public void setSupportsHstsPreloading(Boolean supportsHstsPreloading) {
        this.supportsHstsPreloading = supportsHstsPreloading;
    }

    public Boolean getSupportsHpkp() {
        return supportsHpkp;
    }

    public void setSupportsHpkp(Boolean supportsHpkp) {
        this.supportsHpkp = supportsHpkp;
    }

    public Boolean getSpeaksHttps() {
        return speaksHttps;
    }

    public void setSpeaksHttps(Boolean speaksHttps) {
        this.speaksHttps = speaksHttps;
    }

    public Integer getHstsMaxAge() {
        return hstsMaxAge;
    }

    public void setHstsMaxAge(Integer hstsMaxAge) {
        this.hstsMaxAge = hstsMaxAge;
    }

    public Integer getHpkpMaxAge() {
        return hpkpMaxAge;
    }

    public void setHpkpMaxAge(Integer hpkpMaxAge) {
        this.hpkpMaxAge = hpkpMaxAge;
    }

    public List<HpkpPin> getNormalHpkpPins() {
        return normalHpkpPins;
    }

    public void setNormalHpkpPins(List<HpkpPin> normalHpkpPins) {
        this.normalHpkpPins = normalHpkpPins;
    }

    public List<HpkpPin> getReportOnlyHpkpPins() {
        return reportOnlyHpkpPins;
    }

    public void setReportOnlyHpkpPins(List<HpkpPin> reportOnlyHpkpPins) {
        this.reportOnlyHpkpPins = reportOnlyHpkpPins;
    }

    public Boolean getSupportsHpkpReportOnly() {
        return supportsHpkpReportOnly;
    }

    public void setSupportsHpkpReportOnly(Boolean supportsHpkpReportOnly) {
        this.supportsHpkpReportOnly = supportsHpkpReportOnly;
    }

    /**
     * Contains identifiers for the Common Bugs Dictionary.
     */
    private static class CommonBugs {
        static String EXTENSION_INTOLERANCE = "extensionIntolerance"; //does it handle unknown extenstions correctly?
        static String VERSION_INTOLERANCE = "versionIntolerance"; //does it handle unknown versions correctly?
        static String CIPHER_SUITE_INTOLERANCE = "cipherSuiteIntolerance"; //does it handle unknown ciphersuites correctly?
        static String CIPHER_SUITE_LENGTH_INTOLERANCE = "cipherSuiteLengthIntolerance512"; //does it handle long ciphersuite length values correctly?
        static String COMPRESSION_INTOLERANCE = "compressionIntolerance"; //does it handle unknown compression algorithms correctly
        static String ALPN_INTOLERANCE = "alpnIntolerance"; //does it handle unknown alpn strings correctly?
        static String CLIENT_HELLO_LENGTH_INTOLERANCE = "clientHelloLengthIntolerance"; // 256 - 511 <-- ch should be bigger than this
        static String NAMED_GROUP_INTOLERANT = "namedGroupIntolerant"; // does it handle unknown groups correctly
        static String EMPTY_LAST_EXTENSION_INTOLERANCE = "emptyLastExtensionIntolerance"; //does it break on empty last extension
        static String NAMED_SIGNATURE_AND_HASH_ALGORITHM_INTOLERANCE = "namedSignatureAndHashAlgorithmIntolerance"; // does it handle signature and hash algorithms correctly
        static String MAX_LENGTH_CLIENT_HELLO_INTOLERANT = "maxLengthClientHelloIntolerant"; // server does not like really big client hello messages
        static String ONLY_SECOND_CIPHERSUITE_BYTE_EVALUATED = "onlySecondCiphersuiteByteEvaluated"; //is only the second byte of the ciphersuite evaluated
        static String IGNORES_CIPHER_SUITE_OFFERING = "ignoresCipherSuiteOffering"; //does it ignore the offered ciphersuites
        static String REFLECTS_CIPHER_SUITE_OFFERING = "reflectsCipherSuiteOffering"; //does it ignore the offered ciphersuites
        static String IGNORES_OFFERED_NAMED_GROUPS = "ignoresOfferedNamedGroups"; //does it ignore the offered named groups
        static String IGNORES_OFFERED_SIGNATURE_AND_HASH_ALGORITHMS = "ignoresOfferedSignatureAndHashAlgorithms"; //does it ignore the sig hash algorithms
    }

    /**
     * Contains identifiers for the Supported Versions Dictionary.
     */
    private static class VersionSupport {
        static String SSL_2 = "supportsSsl2";
        static String SSL_3 = "supportsSsl3";
        static String TLS_10 = "supportsTls10";
        static String TLS_11 = "supportsTls11";
        static String TLS_12 = "supportsTls12";
        static String TLS_13 = "supportsTls13";
        static String TLS_13_DRAFT_14 = "supportsTls13Draft14";
        static String TLS_13_DRAFT_15 = "supportsTls13Draft15";
        static String TLS_13_DRAFT_16 = "supportsTls13Draft16";
        static String TLS_13_DRAFT_17 = "supportsTls13Draft17";
        static String TLS_13_DRAFT_18 = "supportsTls13Draft18";
        static String TLS_13_DRAFT_19 = "supportsTls13Draft19";
        static String TLS_13_DRAFT_20 = "supportsTls13Draft20";
        static String TLS_13_DRAFT_21 = "supportsTls13Draft21";
        static String TLS_13_DRAFT_22 = "supportsTls13Draft22";
        static String TLS_13_DRAFT_23 = "supportsTls13Draft23";
        static String TLS_13_DRAFT_24 = "supportsTls13Draft24";
        static String TLS_13_DRAFT_25 = "supportsTls13Draft25";
        static String TLS_13_DRAFT_26 = "supportsTls13Draft26";
        static String TLS_13_DRAFT_27 = "supportsTls13Draft27";
        static String TLS_13_DRAFT_28 = "supportsTls13Draft28";
        static String DTLS_10 = "supportsDtls10";
        static String DTLS_12 = "supportsDtls12";
        static String DTLS_13 = "supportsDtls13";
    }

    /**
     * Contains identifiers for the Certificate Qualities Dictionary.
     */
    private static class CertificateQualities {
        static String EXPIRED = "certificateExpired";
        static String NOT_YET_VALID = "certificateNotYetValid";
        static String WEAK_HASH_ALGORITHM = "certificateHasWeakHashAlgorithm";
        static String WEAK_SIGN_ALGORITHM = "certificateHasWeakSignAlgorithm";
        static String MATCHES_DOMAIN_NAME = "certificateMatchesDomainName";
        static String IS_TRUSTED = "certificateIsTrusted";
        static String KEY_IS_BLACKLISTED = "certificateKeyIsBlacklisted";
    }

    private static class CipherSupport {
        static String NULL_CIPHERS = "supportsNullCiphers";
        static String ANON_CIPHERS = "supportsAnonCiphers";
        static String EXPORT_CIPHERS = "supportsExportCiphers";
        static String DES_CIPHERS = "supportsDesCiphers";
        static String SEED_CIPHERS = "supportsSeedCiphers";
        static String IDEA_CIPHERS = "supportsIdeaCiphers";
        static String RC2_CIPHERS = "supportsRc2Ciphers";
        static String RC4_CIPHERS = "supportsRc4Ciphers";
        static String TRIPLE_DES_CIPHERS = "supportsTrippleDesCiphers";
        static String POST_QUANTUM_CIPHERS = "supportsPostQuantumCiphers";
        static String AEAD_CIPHERS = "supportsAeadCiphers";
        static String PFS_CIPHERS = "supportsPfsCiphers";
        static String ONLY_PFS_CIPHERS = "supportsOnlyPfsCiphers";
        static String ENFORCES_CIPHER_SUITE_ORDERING = "enforcesCipherSuiteOrdering";
        static String AES = "supportsAes";
        static String CAMELLIA = "supportsCamellia";
        static String ARIA = "supportsAria";
        static String CHACHA = "supportsChacha";
        static String RSA = "supportsRsa";
        static String DH = "supportsDh";
        static String ECDH = "supportsEcdh";
        static String STATIC_ECDH = "supportsStaticEcdh";
        static String GOST = "supportsGost";
        static String SRP = "supportsSrp";
        static String KERBEROS = "supportsKerberos";
        static String PSK_PLAIN = "supportsPskPlain";
        static String PSK_RSA = "supportsPskRsa";
        static String PSK_DHE = "supportsPskDhe";
        static String PSK_ECDHE = "supportsPskEcdhe";
        static String FORTEZZA = "supportsFortezza";
        static String NEW_HOPE = "supportsNewHope";
        static String ECMQV = "supportsEcmqv";
        static String PREFERS_PFS_CIPHERS = "prefersPfsCiphers";
        static String STREAM_CIPHERS = "supportsStreamCiphers";
        static String BLOCK_CIPHERS = "supportsBlockCiphers";
    }
}
