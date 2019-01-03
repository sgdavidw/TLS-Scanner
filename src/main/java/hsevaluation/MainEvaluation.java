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
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class MainEvaluation {

    public static final String FOLDER = "Evaluation_Scans";
    public static final int THREADS = 1;
    public static final int AGGRO = 1;

    private static final String LIST = "top-1m.csv";
    private static final int NUMBER_OF_WEBSITES = 250;
    private static final int EXTRACTING_THREADS = 16;

    public static void main(String[] args) {

        System.out.println("##############################################################");
        System.out.println("Starting Evaluation");
        System.out.println("##############################################################");

        System.out.println("Creating Folder '" + FOLDER + "'...");
        createFolder(FOLDER);

        File urlFile = new File(LIST);
        System.out.println("Reading '" + urlFile + "'...");
        List<String> urls = getCsvList(urlFile);

        System.out.println("Extracting Handshake Simulation Reports...");
        performExtraction(urls);
        System.out.println("Extracting Handshake Simulation Reports Finished");

        System.out.println("Evaluating Handshake Simulation Reports...");
        List<HSRes> hsResList = getAllExtractedReports(urls);
        System.out.println("Evaluating Handshake Simulation Reports Finished");

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
        directory.mkdir();
    }

    private static List<String> getCsvList(File file) {
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

    private static void performExtraction(List<String> urls) {
        ThreadPoolExecutor executor
                = (ThreadPoolExecutor) Executors.newFixedThreadPool(EXTRACTING_THREADS);
        for (String url : urls) {
            executor.submit(new HSResExtractor(url));
        }
        executor.shutdown();
        try {
            while (!executor.awaitTermination(10, TimeUnit.SECONDS)) {
                //
            }
        } catch (InterruptedException ex) {
            Logger.getLogger(MainEvaluation.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    private static List<HSRes> getAllExtractedReports(List<String> urls) {
        List<HSRes> hSResList = new LinkedList<>();
        File hSResFile;
        for (String url : urls) {
            hSResFile = new File(FOLDER + "/" + url + ".xml");
            if (hSResFile.exists()) {
                System.out.println("Reading File '" + hSResFile + "'...");
                hSResList.add(HSResIO.read(hSResFile));
            }
        }
        return hSResList;
    }

    private static void performEvaluation(List<HSRes> hSResList) {
        int supportsTlsCounter = 0;
        for (HSRes hSRes : hSResList) {
            if (hSRes.getSupportsSslTls() != null && hSRes.getSupportsSslTls()) {
                supportsTlsCounter++;
                System.out.println(hSRes.getHost() + " tls yes");
            } else {
                System.out.println(hSRes.getHost() + " tls no");
            }
        }
        System.out.println("");
        System.out.println("Tested Websites: " + hSResList.size());
        System.out.println("");
        System.out.println("Support TLS: " + supportsTlsCounter);
        System.out.println("Do not support TLS: " + (hSResList.size() - supportsTlsCounter));
        System.out.println("");
    }
}
