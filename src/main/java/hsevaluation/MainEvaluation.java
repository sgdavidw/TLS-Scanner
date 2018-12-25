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
    private static final String LIST = "top-1m.csv";
    private static final int NUMBER_OF_WEBSITES = 40;
    private static final int THREADS = 6;
    private static final int AGGRO = 10;

    private static GeneralDelegate generalDelegate = null;
    private static ClientDelegate clientDelegate = null;

    public static void main(String args[]) {

        System.out.println("##############################################################");
        System.out.println("Starting Evaluation");
        System.out.println("##############################################################");

        generalDelegate = new GeneralDelegate();
        clientDelegate = new ClientDelegate();

        System.out.println("Creating Folder '" + FOLDER + "'...");
        createFolder(FOLDER);

        File urlFile = new File(LIST);
        System.out.println("Reading '" + urlFile + "'...");
        List<String> urls = readListCsv(urlFile);

        SiteReport report;
        HSRes hSRes;
        File hSResFile;
        long time;

        System.out.println("");
        System.out.println("Extracting Handshake Simulation Reports...");
        System.out.println("");
        
        for (String url : urls) {
            hSResFile = new File(FOLDER + "/" + url + ".xml");
            if (!hSResFile.exists()) {
                System.out.println("");
                System.out.println("Extracting '" + url + "'");
                System.out.println("");
                time = System.currentTimeMillis();
                report = getReportFrom(url);
                hSRes = createHSRes(report);
                System.out.println("Writing File '" + hSResFile + "', this may take some time...");
                HSResIO.write(hSRes, hSResFile);
                System.out.println("");
                System.out.println("Extracted '" + url + "' in:" + ((System.currentTimeMillis() - time) / 1000) + "s\n");
                System.out.println("");
            }
        }

        List<HSRes> hSResList = new LinkedList<>();

        System.out.println("");
        System.out.println("Evaluating Handshake Simulation Reports...");
        System.out.println("");
        
        for (String url : urls) {
            hSResFile = new File(FOLDER + "/" + url + ".xml");
            if (hSResFile.exists()) {
                System.out.println("Reading File '" + hSResFile + "'...");
                hSResList.add(HSResIO.read(hSResFile));
            }
        }

        System.out.println("");
        System.out.println("##############################################################");
        System.out.println("Evaluation Results");
        System.out.println("##############################################################");

        performEvaluation(hSResList);

        System.out.println("##############################################################");
        System.out.println("Evaluation Completed");
        System.out.println("##############################################################");
    }

    private static void performEvaluation(List<HSRes> hSResList) {
        int supportsTlsCounter = 0;
        for (HSRes hSRes : hSResList) {
            if (hSRes.getSupportsSslTls()) {
                supportsTlsCounter++;
            }
        }
        System.out.println("");
        System.out.println("Tested Websites: " + hSResList.size());
        System.out.println("");
        System.out.println("Support TLS: " + supportsTlsCounter);
        System.out.println("Do not support TLS: " + (hSResList.size() - supportsTlsCounter));
        System.out.println("");
    }

    private static SiteReport getReportFrom(String host) {
        SiteReport report = null;
        System.out.println("Getting Report of '" + host + "':");
        clientDelegate.setHost(host);
        ScannerConfig config = new ScannerConfig(generalDelegate, clientDelegate);
        config.setThreads(THREADS);
        config.setAggroLevel(AGGRO);
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

    private static List<String> readListCsv(File file) {
        String line = "";
        String cvsSplitBy = ",";
        List<String> urls = new LinkedList<>();
        int counter = 1;
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            while ((line = br.readLine()) != null && counter <= NUMBER_OF_WEBSITES) {
                String[] url = line.split(cvsSplitBy);
                System.out.println(url[0] + ", " + url[1]);
                urls.add(url[1]);
                counter++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return urls;
    }

    private static HSRes createHSRes(SiteReport report) {
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

    private static void createFolder(String path) {
        File directory = new File(path);
        directory.mkdir();
    }
}
