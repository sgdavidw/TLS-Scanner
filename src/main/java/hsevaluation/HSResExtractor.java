/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsevaluation;

import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.AnsiEscapeSequence;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.File;
import java.util.LinkedList;
import java.util.List;

public class HSResExtractor implements Runnable {

    private final String url;
    private final List<String> log;

    public HSResExtractor(String url) {
        this.url = url;
        this.log = new LinkedList<>();
    }

    @Override
    public void run() {
        File hsResFile = new File(MainEvaluation.FOLDER + "/" + url + ".xml");
        if (!hsResFile.exists()) {
            extractHsres(url, hsResFile);
        }
    }

    private void extractHsres(String url, File hsResFile) {
        System.out.println(Thread.currentThread().getName() + " Extracting '" + url + "' ...");
        log.add("Extracting '" + url + "' ...");
        log.add("");
        long time = System.currentTimeMillis();
        SiteReport report = getReportFrom(url);
        HSRes hSRes = createHSRes(report);
        log.add("Writing File '" + hsResFile + "', this may take some time...");
        HSResIO.write(hSRes, hsResFile);
        log.add("");
        System.out.println(Thread.currentThread().getName() + "Extracted '" + url + "' in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
        log.add("Extracted '" + url + "' in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
        log.add("");
    }

    private SiteReport getReportFrom(String host) {
        SiteReport report = null;
        log.add("Getting Report of '" + host + "':");
        
        GeneralDelegate generalDelegate = new GeneralDelegate();
        ClientDelegate clientDelegate = new ClientDelegate();
        clientDelegate.setHost(host);
        
        ScannerConfig config = new ScannerConfig(generalDelegate, clientDelegate);
        config.setThreads(MainEvaluation.THREADS);
        config.setAggroLevel(MainEvaluation.AGGRO);
        config.setScanDetail(ScannerDetail.ALL);
        
        try {
            TlsScanner scanner = new TlsScanner(config);
            long time = System.currentTimeMillis();
            log.add("Performing Scan, this may take some time...");
            report = scanner.scan();
            log.add("Scanned in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
            if (!config.getGeneralDelegate().isDebug()) {
                // ANSI escape sequences to erase the progressbar
                log.add(AnsiEscapeSequence.ANSI_ONE_LINE_UP + AnsiEscapeSequence.ANSI_ERASE_LINE);
            }
            //ConsoleLogger.CONSOLE.info("Scanned in: " + ((System.currentTimeMillis() - time) / 1000) + "s\n" + report.getFullReport(config.getReportDetail()));
        } catch (ConfigurationException E) {
            log.add("Encountered a ConfigurationException aborting.");
            log.add(E.toString());
        }
        return report;
    }

    private HSRes createHSRes(SiteReport report) {
        HSRes hSRes = new HSRes();
        hSRes.createHSRes(report.getHost());
        hSRes.setSupportsSslTls(report.getSupportsSslTls());
        hSRes.setHandshakeSuccessfulCounter(report.getHandshakeSuccessfulCounter());
        hSRes.setHandshakeFailedCounter(report.getHandshakeFailedCounter());
        hSRes.setConnectionRfc7918SecureCounter(report.getConnectionRfc7918SecureCounter());
        hSRes.setConnectionInsecureCounter(report.getConnectionInsecureCounter());
        hSRes.setSimulatedClientList(report.getSimulatedClientList());
        return hSRes;
    }
}
