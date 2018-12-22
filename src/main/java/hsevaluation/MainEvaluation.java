/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsevaluation;

import de.rub.nds.tlsattacker.core.config.delegate.ClientDelegate;
import de.rub.nds.tlsattacker.core.config.delegate.GeneralDelegate;
import de.rub.nds.tlsattacker.core.exceptions.ConfigurationException;
import de.rub.nds.tlsscanner.ConsoleLogger;
import de.rub.nds.tlsscanner.TlsScanner;
import de.rub.nds.tlsscanner.config.ScannerConfig;
import de.rub.nds.tlsscanner.constants.AnsiEscapeSequence;
import de.rub.nds.tlsscanner.constants.ScannerDetail;
import de.rub.nds.tlsscanner.report.SiteReport;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;

public class MainEvaluation {

    private static final String FOLDER = "Evaluation_Scans";
    private static final String LIST = "top-1m-test.csv";

    private static GeneralDelegate generalDelegate = null;
    private static ClientDelegate clientDelegate = null;

    public static void main(String args[]) {

        System.out.println("");
        System.out.println("Starting Evaluation");
        System.out.println("");
        
        generalDelegate = new GeneralDelegate();
        clientDelegate = new ClientDelegate();

        createFolder(FOLDER);
        List<String> urls = loadListCsv(new File(LIST));

        SiteReport report;
        HSRes hSRes;
        File hSResFile;
        long time;

        for (String url : urls) {
            System.out.println("");
            System.out.println("Evaluating '" + url + "'");
            System.out.println("");
            time = System.currentTimeMillis();
            report = getReportFrom(url);
            hSRes = createHSRes(report);
            hSResFile = new File(FOLDER + "/" + url + ".xml");
            System.out.println("Writing File '" + hSResFile + "', this may take some time...");
            HSResIO.write(hSRes, hSResFile);
            System.out.println("");
            System.out.println("Extracted '" + url + "' in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
            System.out.println("");
        }
        System.out.println("");
        System.out.println("Evaluation Completed");
    }

    private static SiteReport getReportFrom(String host) {
        SiteReport report = null;
        System.out.println("Getting Report of '" + host + "':");
        clientDelegate.setHost(host);
        ScannerConfig config = new ScannerConfig(generalDelegate, clientDelegate);
        config.setThreads(10);
        config.setAggroLevel(18);
        config.setScanDetail(ScannerDetail.ALL);
        try {
            TlsScanner scanner = new TlsScanner(config);
            long time = System.currentTimeMillis();
            System.out.println("Performing Scan, this may take some time...");
            report = scanner.scan();
            System.out.println("Scanned in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
            if (!config.getGeneralDelegate().isDebug()) {
                // ANSI escape sequences to erase the progressbar
                ConsoleLogger.CONSOLE.info(AnsiEscapeSequence.ANSI_ONE_LINE_UP + AnsiEscapeSequence.ANSI_ERASE_LINE);
            }
            //ConsoleLogger.CONSOLE.info("Scanned in: " + ((System.currentTimeMillis() - time) / 1000) + "s\n" + report.getFullReport(config.getReportDetail()));
        } catch (ConfigurationException E) {
            System.out.println("Encountered a ConfigurationException aborting.");
            System.err.println(E);
        }
        return report;
    }

    private static List<String> loadListCsv(File file) {
        System.out.println("Loading '" + file + "' ...");
        String line = "";
        String cvsSplitBy = ",";
        List<String> urls = null;
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            urls = new LinkedList<>();
            while ((line = br.readLine()) != null) {
                String[] url = line.split(cvsSplitBy);
                System.out.println(url[0] + ", " + url[1]);
                urls.add(url[1]);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return urls;
    }

    private static HSRes createHSRes(SiteReport report) {
        HSRes hSRes = new HSRes();
        hSRes.createHSRes(report.getHost());
        hSRes.setHandshakeSuccessfulCounter(report.getHandshakeSuccessfulCounter());
        hSRes.setHandshakeFailedCounter(report.getHandshakeFailedCounter());
        hSRes.setConnectionRfc7918SecureCounter(report.getConnectionRfc7918SecureCounter());
        hSRes.setConnectionInsecureCounter(report.getConnectionInsecureCounter());
        hSRes.setSimulatedClientList(report.getSimulatedClientList());
        return hSRes;
    }

    private static void createFolder(String path) {
        System.out.println("Creating Folder '" + path + "' ...");
        File directory = new File(path);
        directory.mkdir();
    }
}
