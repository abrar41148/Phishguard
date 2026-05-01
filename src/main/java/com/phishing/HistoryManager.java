package com.phishing;

import java.io.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.List;

public class HistoryManager {

    private static final String HISTORY_FILE = "history.csv";
    private static final DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private static final Object lock = new Object();
    private static int writeCounter = 0;

    public static void logScan(String url, RiskReport report) {
        synchronized(lock) {
            File file = new File(HISTORY_FILE);
            boolean isNewFile = !file.exists();

            try (PrintWriter writer = new PrintWriter(new FileWriter(file, true))) {
                if (isNewFile) {
                    // Header
                    writer.println("Timestamp,URL,Result,Score,Source,Details");
                }
                
                // Format data
                String timestamp = LocalDateTime.now().format(formatter);
                String safeUrl = SecurityUtils.sanitizeForCSV(url);
                String result = SecurityUtils.sanitizeForCSV(report.getResult().name());
                String score = String.valueOf(report.getScore());
                String source = SecurityUtils.sanitizeForCSV(report.getSource());
                // Join details with pipe delimiter and wrap in quotes
                String details = String.join("|", report.getDetails()).replace("\"", "'");

                writer.println(SecurityUtils.sanitizeForCSV(timestamp) + "," + safeUrl + "," + result + "," + score + "," + source + ",\"" + details + "\"");
                
            } catch (IOException e) {
                System.out.println("Failed to write to history file.");
            }

            writeCounter++;
            if (writeCounter % 50 == 0) {
                enforceHistoryLimit();
            }
        }
    }

    private static void enforceHistoryLimit() {
        File file = new File(HISTORY_FILE);
        if (!file.exists()) return;

        try {
            java.util.List<String> lines = java.nio.file.Files.readAllLines(file.toPath());
            if (lines.size() > 1000) {
                // Keep header (index 0), and then keep the most recent 800
                int keepCount = 800;
                java.util.List<String> newLines = new ArrayList<>();
                newLines.add(lines.get(0)); // header
                
                int startIdx = lines.size() - keepCount;
                if (startIdx < 1) startIdx = 1;
                
                newLines.addAll(lines.subList(startIdx, lines.size()));
                
                java.nio.file.Files.write(file.toPath(), newLines);
            }
        } catch (Exception e) {
            System.out.println("Failed to truncate history file.");
        }
    }

    public static void clearHistory() {
        File file = new File(HISTORY_FILE);
        if (file.exists()) {
            file.delete();
        }
    }
    
    /**
     * Parses a CSV line according to RFC 4180 standard.
     * Properly handles:
     * - Quoted fields that may contain commas
     * - Escaped quotes (represented as doubled quotes within a quoted field)
     * - Unquoted fields
     * - Tab-prefixed fields (CSV injection prevention)
     * 
     * @param line The CSV line to parse
     * @return List of parsed fields (unquoted and unescaped)
     */
    private static List<String> parseCSVLine(String line) {
        List<String> tokens = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inQuotes = false;
        
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            char next = (i + 1 < line.length()) ? line.charAt(i + 1) : '\0';
            
            if (c == '"') {
                if (inQuotes && next == '"') {
                    // Escaped quote: two consecutive quotes within a quoted field = one literal quote
                    current.append('"');
                    i++; // Skip the next quote
                } else {
                    // Toggle quote mode
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                // Field separator (only if not inside quotes)
                tokens.add(postProcessField(current.toString()));
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        
        // Add the last field
        tokens.add(postProcessField(current.toString()));
        
        return tokens;
    }
    
    /**
     * Post-processes a parsed CSV field.
     * Removes surrounding quotes (if present) and strips leading tabs used for CSV injection prevention.
     * 
     * @param field The raw field value from CSV parsing
     * @return Cleaned field value ready for use
     */
    private static String postProcessField(String field) {
        String result = field.trim();
        
        // Remove surrounding quotes if present
        if (result.length() >= 2 && result.startsWith("\"") && result.endsWith("\"")) {
            result = result.substring(1, result.length() - 1);
        }
        
        // Remove leading tab used for CSV injection prevention (safety measure)
        if (result.length() > 0 && result.charAt(0) == '\t') {
            result = result.substring(1);
        }
        
        return result;
    }
    
    public static List<String[]> getHistory() {
        List<String[]> rows = new ArrayList<>();
        File file = new File(HISTORY_FILE);
        if (!file.exists()) return rows;

        try (BufferedReader br = new BufferedReader(new FileReader(file))) {
            String line;
            boolean isHeader = true;
            while ((line = br.readLine()) != null) {
                if (isHeader) {
                    isHeader = false;
                    continue;
                }
                
                // Use proper RFC 4180 CSV parser
                List<String> columns = parseCSVLine(line);
                
                // Validate row has minimum columns
                if (columns.size() >= 6) {
                    rows.add(new String[]{columns.get(0), columns.get(1), columns.get(2), columns.get(3), columns.get(4), columns.get(5)});
                } else if (columns.size() >= 5) {
                    rows.add(new String[]{columns.get(0), columns.get(1), columns.get(2), columns.get(3), columns.get(4), ""});
                } else if (columns.size() >= 4) {
                    // Legacy rows without score/details
                    rows.add(new String[]{columns.get(0), columns.get(1), columns.get(2), "--", columns.get(3), ""});
                } else {
                    // Malformed row - skip silently
                    System.out.println("[HistoryManager] Skipping malformed CSV row: " + line);
                }
            }
        } catch (IOException e) {
            System.err.println("[HistoryManager] Error reading history file: " + e.getMessage());
            e.printStackTrace();
        }
        return rows;
    }
}
