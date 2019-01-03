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
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.File;

public class HSResExtractor implements Runnable {

    private final String url;

    public HSResExtractor(String url) {
        this.url = url;
    }

    @Override
    public void run() {
        File hsResFile = new File(Main.FOLDER + "/" + url + ".xml");
        if (!hsResFile.exists()) {
            extractHsres(url, hsResFile);
        }
    }

    private void extractHsres(String url, File hsResFile) {
//        System.out.println(Thread.currentThread().getName() + " - Extracting '" + url + "' ...");
        long time = System.currentTimeMillis();
        SiteReport report = getReportFrom(url);
        HSRes hSRes = createHSRes(report);
        HSResIO.write(hSRes, hsResFile);
//        System.out.println(Thread.currentThread().getName() + " - Extracted '" + url + "' in: " + ((System.currentTimeMillis() - time) / 1000) + "s");
        LogEntries.add("Extracted '" + url + "' in:" + ((System.currentTimeMillis() - time) / 1000) + "s");
    }

    private SiteReport getReportFrom(String host) {
        SiteReport report = null;

        GeneralDelegate generalDelegate = new GeneralDelegate();
        ClientDelegate clientDelegate = new ClientDelegate();
        clientDelegate.setHost(host);

        ScannerConfig config = new ScannerConfig(generalDelegate, clientDelegate);
        config.setThreads(Main.THREADS);
        config.setAggroLevel(Main.AGGRO);
        config.setScanDetail(ScannerDetail.ALL);

        try {
            TlsScanner scanner = new TlsScanner(config);
//            long time = System.currentTimeMillis();
//            LOGGER.info("Performing Scan, this may take some time...");
            report = scanner.scan();
//            LOGGER.info("Scanned in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
            if (!config.getGeneralDelegate().isDebug()) {
                // ANSI escape sequences to erase the progressbar
//                ConsoleLogger.CONSOLE.info(AnsiEscapeSequence.ANSI_ONE_LINE_UP + AnsiEscapeSequence.ANSI_ERASE_LINE);
            }
//            ConsoleLogger.CONSOLE.info("Scanned in: " + ((System.currentTimeMillis() - time) / 1000) + "s\n" + report.getFullReport(config.getReportDetail()));
        } catch (ConfigurationException E) {
            System.err.println("Encountered a ConfigurationException aborting.");
            System.err.println(E);
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
