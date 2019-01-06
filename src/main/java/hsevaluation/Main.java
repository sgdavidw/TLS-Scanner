/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsevaluation;

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
    
    // Evaluation 1

    public static final String FOLDER_ALL = "Evaluation_Scans_a";
    public static final String FOLDER_DEFAULT = "Evaluation_Scans_d";
    public static final int THREADS = 1;
    public static final int AGGRO = 1;
    
    public static String FOLDER;

    private static final String LIST = "top-1m.csv";
    private static final int START_NUMBER = 1;
    private static final int NUMBER_OF_WEBSITES = 1000;
    private static final int EXTRACTING_THREADS = 16;
    private static final boolean TEST_DEFAULT_VERSIONS = true;

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
        int cSecure = 0;
        int cInsecure = 0;
        int testedClients = 0;
        double tmp1;
        double tmp2;
        double tmp3;
        if (TEST_DEFAULT_VERSIONS) {
            testedClients = 12;
        } else {
            testedClients = 270;
        }
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
        System.out.println("Connections - Secure: " + cSecure);
        System.out.println("Connections - Insecure: " + cInsecure);
        System.out.println("Connections - Undefined: " + (hsSuccessful - cSecure - cInsecure));
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
