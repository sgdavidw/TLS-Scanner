/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsevaluation;

import de.rub.nds.tlsscanner.probe.handshakeSimulation.ConnectionInsecure;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.HandshakeFailed;
import de.rub.nds.tlsscanner.probe.handshakeSimulation.SimulatedClient;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.logging.Level;
import java.util.logging.Logger;
import me.tongfei.progressbar.ProgressBar;

public class Main {

    public static final String FOLDER_ALL = "Evaluation_Scans_a";
    public static final String FOLDER_DEFAULT = "Evaluation_Scans_d";
    public static final int THREADS = 1;
    public static final int AGGRO = 1;

    public static String FOLDER;

    private static final String LIST = "top-1m.csv";
    private static final int START_NUMBER = 1;
    private static final int NUMBER_OF_WEBSITES = 1000;
    private static final int EXTRACTING_THREADS = 16;

    public static final boolean TEST_DEFAULT_VERSIONS = true;

    public static void main(String[] args) {

        System.out.println("##############################################################");
        System.out.println("Starting Evaluation");
        System.out.println("##############################################################");

        if (TEST_DEFAULT_VERSIONS) {
            FOLDER = FOLDER_DEFAULT;
        } else {
            FOLDER = FOLDER_ALL;
        }

        createFolder(FOLDER);

        File urlFile = new File(LIST);
        System.out.println("Reading '" + urlFile + "'...");
        List<String> urls = getCsvList(urlFile);
        System.out.println("Reading '" + urlFile + "' Finished");

        System.out.println("Extracting Handshake Simulation Reports...");
        performExtraction(urls);
        System.out.println("Extracting Handshake Simulation Reports Finished");

        System.out.println("Loading Handshake Simulation Reports...");
        List<HSRes> hsResList = getAllExtractedReports(urls);
        System.out.println("Loading Handshake Simulation Reports Finished");

        System.out.println("##############################################################");
        System.out.println("Evaluation Results");
        System.out.println("##############################################################");
        performEvaluation(hsResList);
        System.out.println("##############################################################");
        System.out.println("Evaluation Finished");
        System.out.println("##############################################################");
    }

    private static void createFolder(String path) {
        File directory = new File(path);
        if (!directory.exists()) {
            System.out.println("Creating Folder '" + FOLDER + "'...");
            directory.mkdir();
        } else {
            System.out.println("Folder '" + FOLDER + "' already exists");
        }
    }

    private static List<String> getCsvList(File file) {
        String line = "";
        String cvsSplitBy = ",";
        List<String> urls = new LinkedList<>();
        int counter = 1;
        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            while ((line = br.readLine()) != null && counter <= NUMBER_OF_WEBSITES) {
                if (counter >= START_NUMBER) {
                    String[] url = line.split(cvsSplitBy);
                    System.out.println(url[0] + ", " + url[1]);
                    urls.add(url[1]);
                }
                counter++;
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return urls;
    }

    private static void performExtraction(List<String> urls) {
        ThreadPoolExecutor executor = (ThreadPoolExecutor) Executors.newFixedThreadPool(EXTRACTING_THREADS);
        for (String url : urls) {
            executor.submit(new HSResExtractor(url));
        }
        executor.shutdown();
        ProgressBar pb = new ProgressBar("", executor.getTaskCount());
        while (true) {
            try {
                Thread.sleep(100);
            } catch (InterruptedException ex) {
                Logger.getLogger(Main.class.getName()).log(Level.SEVERE, null, ex);
            }
            pb.stepTo(executor.getCompletedTaskCount());
            if (executor.isTerminated()) {
                pb.stepTo(pb.getMax());
                pb.close();
                break;
            }
        }
        System.out.println("");
        System.out.println("Extraction Log:");
        if (LogEntries.getEntries().isEmpty()) {
            System.out.println("-");
        } else {
            for (String logEntry : LogEntries.getEntries()) {
                System.out.println(logEntry);
            }
        }
    }

    private static List<HSRes> getAllExtractedReports(List<String> urls) {
        List<HSRes> hSResList = new LinkedList<>();
        File hSResFile;
        ProgressBar pb = new ProgressBar("", urls.size());
        for (String url : urls) {
            hSResFile = new File(FOLDER + "/" + url + ".xml");
            if (hSResFile.exists()) {
                hSResList.add(HSResIO.read(hSResFile));
            }
            pb.step();
        }
        pb.close();
        for (String url : urls) {
            hSResFile = new File(FOLDER + "/" + url + ".xml");
            if (!hSResFile.exists()) {
                System.out.println("INFO: File for '" + url + "' does not exists");
            }
        }
        return hSResList;
    }

    private static void performEvaluation(List<HSRes> hSResList) {
        int sTlsNull = 0;
        int sTlsTrue = 0;
        int sTlsTrueButHsMissing = 0;
        int hsSuccessful = 0;
        int hsFailed = 0;
        int fPM = 0;
        int fCM = 0;
        int fPE = 0;
        int fCF = 0;
        int fRSAK = 0;
        int fDHK = 0;
        int fU = 0;
        int iCGL = 0;
        int iPKS = 0;
        int iPksRsa = 0;
        int iPksDh = 0;
        int iPksEcdh = 0;
        int iPO = 0;
        int iB = 0;
        int iC = 0;
        int iS = 0;
        int cSecure = 0;
        int cInsecure = 0;
        int testedClients = 0;
        double tmp1;
        double tmp2;
        double tmp3;
        for (HSRes hSRes : hSResList) {
            if (hSRes.getSupportsSslTls() != null) {
                if (hSRes.getSupportsSslTls()) {
                    sTlsTrue++;
                    if (hSRes.getHandshakeSuccessfulCounter() == null || hSRes.getHandshakeFailedCounter() == null
                            || hSRes.getConnectionInsecureCounter() == null || hSRes.getConnectionRfc7918SecureCounter() == null
                            || hSRes.getSimulatedClientList() == null) {
                        sTlsTrueButHsMissing++;
                    } else {
                        hsSuccessful = hsSuccessful + hSRes.getHandshakeSuccessfulCounter();
                        hsFailed = hsFailed + hSRes.getHandshakeFailedCounter();
                        cSecure = cSecure + hSRes.getConnectionRfc7918SecureCounter();
                        cInsecure = cInsecure + hSRes.getConnectionInsecureCounter();
                        testedClients = hSRes.getSimulatedClientList().size();
                        for (SimulatedClient simulatedClient : hSRes.getSimulatedClientList()) {
                            if (simulatedClient.getHandshakeSuccessful() != null && !simulatedClient.getHandshakeSuccessful()) {
                                if (!simulatedClient.getFailReasons().isEmpty()) {
                                    for (String fReason : simulatedClient.getFailReasons()) {
                                        if (fReason.contains(HandshakeFailed.PROTOCOL_MISMATCH.getReason())) {
                                            fPM++;
                                        }
                                        if (fReason.contains(HandshakeFailed.CIPHERSUITE_MISMATCH.getReason())) {
                                            fCM++;
                                        }
                                        if (fReason.contains(HandshakeFailed.PARSING_ERROR.getReason())) {
                                            fPE++;
                                        }
                                        if (fReason.contains(HandshakeFailed.CIPHERSUITE_FORBIDDEN.getReason())) {
                                            fCF++;
                                        }
                                        if (fReason.contains(HandshakeFailed.PUBLIC_KEY_SIZE_RSA_NOT_ACCEPTED.getReason())) {
                                            fRSAK++;
                                        }
                                        if (fReason.contains(HandshakeFailed.PUBLIC_KEY_SIZE_DH_NOT_ACCEPTED.getReason())) {
                                            fDHK++;
                                        }
                                        if (fReason.contains(HandshakeFailed.UNKNOWN.getReason())) {
                                            fU++;
                                        }
                                    }
                                }
                            }
                            if (simulatedClient.getConnectionInsecure() != null && simulatedClient.getConnectionInsecure()) {
                                if (!simulatedClient.getInsecureReasons().isEmpty()) {
                                    for (String iReason : simulatedClient.getInsecureReasons()) {
                                        if (iReason.contains(ConnectionInsecure.CIPHERSUITE_GRADE_LOW.getReason())) {
                                            iCGL++;
                                        }
                                        if (iReason.contains(ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL.getReason())) {
                                            iPKS++;
                                            if (iReason.contains("rsa")) {
                                                iPksRsa++;
                                            }
                                            if (iReason.contains("dh")) {
                                                iPksDh++;
                                            }
                                            if (iReason.contains("ecdh")) {
                                                iPksEcdh++;
                                            }
                                        }
                                        if (iReason.contains(ConnectionInsecure.PADDING_ORACLE.getReason())) {
                                            iPO++;
                                        }
                                        if (iReason.contains(ConnectionInsecure.BLEICHENBACHER.getReason())) {
                                            iB++;
                                        }
                                        if (iReason.contains(ConnectionInsecure.CRIME.getReason())) {
                                            iC++;
                                        }
                                        if (iReason.contains(ConnectionInsecure.SWEET32.getReason())) {
                                            iS++;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            } else {
                sTlsNull++;
            }
        }
        System.out.println("");
        System.out.println("Tested Webserver: " + hSResList.size());
        System.out.println("Tested Clients Per Webserver: " + testedClients);
        System.out.println("");
        System.out.println("TLS - True: " + sTlsTrue);
        System.out.println("TLS - False: " + (hSResList.size() - sTlsNull - sTlsTrue));
        System.out.println("TLS - Undefined: " + sTlsNull);
        System.out.println("");
        System.out.println("Handshake Data - Available: " + (sTlsTrue - sTlsTrueButHsMissing));
        System.out.println("Handshake Data - Not Available: " + sTlsTrueButHsMissing);
        System.out.println("");
        System.out.println("Handshakes - Total: " + (hsSuccessful + hsFailed));
        System.out.println("Handshakes - Successful: " + hsSuccessful);
        System.out.println("Handshakes - Failed: " + hsFailed);
        System.out.println("");
        System.out.println("Fail Reason " + HandshakeFailed.PROTOCOL_MISMATCH + ": " + fPM);
        System.out.println("Fail Reason " + HandshakeFailed.CIPHERSUITE_MISMATCH + ": " + fCM);
        System.out.println("Fail Reason " + HandshakeFailed.PARSING_ERROR + ": " + fPE);
        System.out.println("Fail Reason " + HandshakeFailed.CIPHERSUITE_FORBIDDEN + ": " + fCF);
        System.out.println("Fail Reason " + HandshakeFailed.PUBLIC_KEY_SIZE_RSA_NOT_ACCEPTED + ": " + fRSAK);
        System.out.println("Fail Reason " + HandshakeFailed.PUBLIC_KEY_SIZE_DH_NOT_ACCEPTED + ": " + fDHK);
        System.out.println("Fail Reason " + HandshakeFailed.UNKNOWN + ": " + fU);
        System.out.println("");
        System.out.println("Connections - Secure: " + cSecure);
        System.out.println("Connections - Insecure: " + cInsecure);
        System.out.println("Connections - Undefined: " + (hsSuccessful - cSecure - cInsecure));
        System.out.println("");
        System.out.println("Insecure Reason " + ConnectionInsecure.CIPHERSUITE_GRADE_LOW + ": " + iCGL);
        System.out.println("Insecure Reason " + ConnectionInsecure.PUBLIC_KEY_SIZE_TOO_SMALL + ": " + iPKS);
        System.out.println("- RSA: " + iPksRsa);
        System.out.println("- DH: " + iPksDh);
        System.out.println("- ECDH: " + iPksEcdh);
        System.out.println("Insecure Reason " + ConnectionInsecure.PADDING_ORACLE + ": " + iPO);
        System.out.println("Insecure Reason " + ConnectionInsecure.BLEICHENBACHER + ": " + iB);
        System.out.println("Insecure Reason " + ConnectionInsecure.CRIME + ": " + iC);
        System.out.println("Insecure Reason " + ConnectionInsecure.SWEET32 + ": " + iS);
        System.out.println("");
        tmp1 = ((double) cSecure) / ((double) hsSuccessful) * 100.0;
        System.out.println("Connections Secure Rate In %: " + tmp1);
        tmp2 = ((double) cInsecure) / ((double) hsSuccessful) * 100.0;
        System.out.println("Connections Insecure Rate In %: " + tmp2);
        tmp3 = 100.0 - tmp1 - tmp2;
        System.out.println("Connections Undefined Rate In %: " + tmp3);
        System.out.println("");
    }
}
