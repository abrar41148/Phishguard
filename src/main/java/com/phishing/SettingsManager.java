package com.phishing;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

public class SettingsManager {
    private static final String SETTINGS_FILE = "settings.properties";
    private Properties props;

    // Singleton instance for global access
    private static SettingsManager instance;

    private SettingsManager() {
        props = new Properties();
        loadSettings();
    }

    public static synchronized SettingsManager getInstance() {
        if (instance == null) {
            instance = new SettingsManager();
        }
        return instance;
    }

    private void loadSettings() {
        File f = new File(SETTINGS_FILE);
        if (f.exists()) {
            try (FileInputStream in = new FileInputStream(f)) {
                props.load(in);
            } catch (IOException e) {
                System.out.println("Failed to load settings: " + e.getMessage());
            }
        } else {
            // Default settings
            props.setProperty("ACTIVE_PROVIDER", "VirusTotal");
            props.setProperty("VIRUS_TOTAL_KEY", "YOUR_API_KEY_HERE");
            props.setProperty("GOOGLE_SAFE_BROWSING_KEY", "YOUR_API_KEY_HERE");
            saveSettings();
        }
    }

    public void saveSettings() {
        try (FileOutputStream out = new FileOutputStream(SETTINGS_FILE)) {
            props.store(out, "Phishing Detector Configurations");
        } catch (IOException e) {
            System.out.println("Failed to save settings: " + e.getMessage());
        }
    }

    /** Keys that contain sensitive data and should be encrypted on disk */
    private static final Set<String> SENSITIVE_KEYS = new HashSet<>(Arrays.asList(
        "VIRUS_TOTAL_KEY", "GOOGLE_SAFE_BROWSING_KEY", "PHISHTANK_KEY"
    ));

    /**
     * Gets a property value. Sensitive keys are automatically decrypted.
     */
    public String getProperty(String key) {
        String value = props.getProperty(key, "");
        if (SENSITIVE_KEYS.contains(key)) {
            return SecurityUtils.decryptKey(value);
        }
        return value;
    }

    public String getProperty(String key, String defaultValue) {
        String value = props.getProperty(key, defaultValue);
        if (SENSITIVE_KEYS.contains(key)) {
            return SecurityUtils.decryptKey(value);
        }
        return value;
    }

    /**
     * Sets a property value. Sensitive keys are automatically encrypted before storage.
     */
    public void setProperty(String key, String value) {
        if (SENSITIVE_KEYS.contains(key)) {
            props.setProperty(key, SecurityUtils.encryptKey(value));
        } else {
            props.setProperty(key, value);
        }
    }
}
