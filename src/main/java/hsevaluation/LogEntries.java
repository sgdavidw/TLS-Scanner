/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hsevaluation;

import java.util.LinkedList;
import java.util.List;

public class LogEntries {

    private static final List<String> entries = new LinkedList<>();

    public static List<String> getEntries() {
        return entries;
    }

    public static void add(String logEntry) {
        synchronized (entries) {
            entries.add(logEntry);
        }
    }
}
