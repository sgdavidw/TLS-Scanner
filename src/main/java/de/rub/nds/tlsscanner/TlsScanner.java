/**
 * TLS-Scanner - A TLS configuration and analysis tool based on TLS-Attacker.
 *
 * Copyright 2017-2019 Ruhr University Bochum / Hackmanit GmbH
 *
 * Licensed under Apache License 2.0
 * http://www.apache.org/licenses/LICENSE-2.0
 */
package de.rub.nds.tlsscanner;

import de.rub.nds.tlsattacker.attacks.connectivity.ConnectivityChecker;
import de.rub.nds.tlsattacker.core.config.Config;
import de.rub.nds.tlsattacker.core.constants.StarttlsType;
import de.rub.nds.tlsattacker.core.workflow.NamedThreadFactory;
import de.rub.nds.tlsattacker.core.workflow.ParallelExecutor;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.ProbeType;
import de.rub.nds.tlsscanner.probe.BleichenbacherProbe;
import de.rub.nds.tlsscanner.probe.CertificateProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteOrderProbe;
import de.rub.nds.tlsscanner.probe.CiphersuiteProbe;
import de.rub.nds.tlsscanner.probe.CommonBugProbe;
import de.rub.nds.tlsscanner.probe.CompressionsProbe;
import de.rub.nds.tlsscanner.probe.DrownProbe;
import de.rub.nds.tlsscanner.probe.EarlyCcsProbe;
import de.rub.nds.tlsscanner.probe.ExtensionProbe;
import de.rub.nds.tlsscanner.probe.HeartbleedProbe;
import de.rub.nds.tlsscanner.probe.HttpHeaderProbe;
import de.rub.nds.tlsscanner.probe.InvalidCurveProbe;
import de.rub.nds.tlsscanner.probe.MacProbe;
import de.rub.nds.tlsscanner.probe.NamedCurvesProbe;
import de.rub.nds.tlsscanner.probe.PaddingOracleProbe;
import de.rub.nds.tlsscanner.probe.PoodleProbe;
import de.rub.nds.tlsscanner.report.SiteReport;
import de.rub.nds.tlsscanner.probe.ProtocolVersionProbe;
import de.rub.nds.tlsscanner.probe.RenegotiationProbe;
import de.rub.nds.tlsscanner.probe.ResumptionProbe;
import de.rub.nds.tlsscanner.probe.SniProbe;
import de.rub.nds.tlsscanner.probe.Tls13Probe;
import de.rub.nds.tlsscanner.probe.TlsPoodleProbe;
import de.rub.nds.tlsscanner.probe.TlsProbe;
import de.rub.nds.tlsscanner.probe.TokenbindingProbe;
import de.rub.nds.tlsscanner.report.after.AfterProbe;
import de.rub.nds.tlsscanner.report.after.DhValueAfterProbe;
import de.rub.nds.tlsscanner.report.after.EcPublicKeyAfterProbe;
import de.rub.nds.tlsscanner.report.after.EvaluateRandomnessAfterProbe;
import de.rub.nds.tlsscanner.report.after.FreakAfterProbe;
import de.rub.nds.tlsscanner.report.after.LogjamAfterprobe;
import de.rub.nds.tlsscanner.report.after.PaddingOracleIdentificationAfterProbe;
import de.rub.nds.tlsscanner.report.after.Sweet32AfterProbe;
import de.rub.nds.tlsscanner.trust.TrustAnchorManager;
import java.util.LinkedList;
import java.util.List;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 *
 * @author Robert Merget - robert.merget@rub.de
 */
public class TlsScanner {

    private final Logger LOGGER = LogManager.getLogger();

    private final ParallelExecutor parallelExecutor;
    private final ScannerConfig config;
    private final boolean closeAfterFinish;
    private final boolean closeAfterFinishParallel;
    private final List<TlsProbe> probeList;
    private final List<AfterProbe> afterList;

    public TlsScanner(ScannerConfig config) {

        this.config = config;
        closeAfterFinish = true;
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3,
                new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ScanJobExecutor executor) {
        this.config = config;
        closeAfterFinish = false;
        closeAfterFinishParallel = true;
        parallelExecutor = new ParallelExecutor(config.getOverallThreads(), 3,
                new NamedThreadFactory(config.getClientDelegate().getHost() + "-Worker"));
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ScanJobExecutor executor, ParallelExecutor parallelExecutor) {
        this.config = config;
        this.parallelExecutor = parallelExecutor;
        closeAfterFinish = false;
        closeAfterFinishParallel = false;
        this.probeList = new LinkedList<>();
        this.afterList = new LinkedList<>();
        fillDefaultProbeLists();
    }

    public TlsScanner(ScannerConfig config, ScanJobExecutor executor, ParallelExecutor parallelExecutor,
            List<TlsProbe> probeList, List<AfterProbe> afterList) {
        this.parallelExecutor = parallelExecutor;
        this.config = config;
        this.probeList = probeList;
        this.afterList = afterList;
        closeAfterFinish = false;
        closeAfterFinishParallel = false;
    }

    private void fillDefaultProbeLists() {
        probeList.add(new CommonBugProbe(config, parallelExecutor));
        // probeList.add(new SniProbe(config, parallelExecutor));
        // probeList.add(new CompressionsProbe(config, parallelExecutor));
        // probeList.add(new NamedCurvesProbe(config, parallelExecutor));
        probeList.add(new CertificateProbe(config, parallelExecutor));
        probeList.add(new ProtocolVersionProbe(config, parallelExecutor));
        probeList.add(new CiphersuiteProbe(config, parallelExecutor));
        // probeList.add(new CiphersuiteOrderProbe(config, parallelExecutor));
        // probeList.add(new ExtensionProbe(config, parallelExecutor));
        // probeList.add(new Tls13Probe(config, parallelExecutor));
        // probeList.add(new TokenbindingProbe(config, parallelExecutor));
        // probeList.add(new HttpHeaderProbe(config, parallelExecutor));
        // probeList.add(new ResumptionProbe(config, parallelExecutor));
        // probeList.add(new RenegotiationProbe(config, parallelExecutor));
        // probeList.add(new HeartbleedProbe(config, parallelExecutor));
        probeList.add(new PaddingOracleProbe(config, parallelExecutor));
        probeList.add(new BleichenbacherProbe(config, parallelExecutor));
        // probeList.add(new PoodleProbe(config, parallelExecutor));
        // probeList.add(new TlsPoodleProbe(config, parallelExecutor));
        // probeList.add(new InvalidCurveProbe(config, parallelExecutor));
        // probeList.add(new DrownProbe(config, parallelExecutor));
        // probeList.add(new EarlyCcsProbe(config, parallelExecutor));
        // probeList.add(new MacProbe(config, parallelExecutor));
        // afterList.add(new Sweet32AfterProbe());
        // afterList.add(new FreakAfterProbe());
        // afterList.add(new LogjamAfterprobe());
        // afterList.add(new EvaluateRandomnessAfterProbe());
        // afterList.add(new EcPublicKeyAfterProbe());
        // afterList.add(new DhValueAfterProbe());
        afterList.add(new PaddingOracleIdentificationAfterProbe());
    }

    public SiteReport scan() {
        LOGGER.debug("Initializing TrustAnchorManager");
        TrustAnchorManager.getInstance();
        LOGGER.debug("Finished TrustAnchorManager initialization");

        boolean isConnectable = false;
        ThreadedScanJobExecutor executor = null;
        try {
            if (isConnectable()) {
                LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                if ((config.getStarttlsDelegate().getStarttlsType() == StarttlsType.NONE && speaksTls())
                        || (config.getStarttlsDelegate().getStarttlsType() != StarttlsType.NONE && speaksStartTls())) {
                    LOGGER.debug(config.getClientDelegate().getHost() + " is connectable");
                    ScanJob job = new ScanJob(probeList, afterList);
                    executor = new ThreadedScanJobExecutor(config, job, config.getOverallThreads(),
                            config.getClientDelegate().getHost());
                    SiteReport report = executor.execute();
                    return report;
                } else {
                    isConnectable = true;
                }
            }
            SiteReport report = new SiteReport(config.getClientDelegate().getHost(), new LinkedList<ProbeType>());
            report.setServerIsAlive(isConnectable);
            report.setSupportsSslTls(false);
            return report;
        } finally {
            if (executor != null) {
                executor.shutdown();
            }
            closeParallelExecutorIfNeeded();
        }
    }

    private void closeParallelExecutorIfNeeded() {

        if (closeAfterFinishParallel) {
            parallelExecutor.shutdown();
        }
    }

    public boolean isConnectable() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.isConnectable();
    }

    private boolean speaksTls() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.speaksTls(tlsConfig);
    }

    private boolean speaksStartTls() {
        Config tlsConfig = config.createConfig();
        ConnectivityChecker checker = new ConnectivityChecker(tlsConfig.getDefaultClientConnection());
        return checker.speaksStartTls(tlsConfig);
    }
}
