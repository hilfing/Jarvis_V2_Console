namespace Jarvis_V2_Console.Handlers;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using IniParser;
using IniParser.Model;
using IniParser.Parser;
using System.Collections.Concurrent;


public static class ConfigManager
{
    private static readonly string ConfigFilePath = Path.Combine(
        AppDomain.CurrentDomain.BaseDirectory,
        "config.ini"
    );

    private static readonly Logger logger = new Logger("JarvisAI.Handlers.ConfigManager"); 

    private static ConcurrentDictionary<string, Dictionary<string, (string Value, string Comment)>> _configStructure;

    static ConfigManager()
    {
        logger.Debug("Initializing ConfigManager...");
        InitializeDefaultConfigStructure();
        LoadOrCreateConfiguration();
    }

    private static void InitializeDefaultConfigStructure()
    {
        logger.Debug("Setting up default configuration structure...");

        _configStructure = new ConcurrentDictionary<string, Dictionary<string, (string, string)>>();

        _configStructure["Database"] = new Dictionary<string, (string, string)>
        {
            ["ConnectionString"] = (
                "Server=localhost;Database=mydb;",
                "Database connection string. Format: Server=host;Database=name;"
            ),
            ["Timeout"] = (
                "30",
                "Connection timeout in seconds"
            )
        };

        _configStructure["Performance"] = new Dictionary<string, (string, string)>
        {
            ["MaxCacheSize"] = (
                "1024",
                "Maximum number of items to keep in memory cache"
            ),
            ["ThreadPoolSize"] = (
                "4",
                "Number of threads in the application thread pool"
            )
        };

        logger.Info("Default configuration structure initialized.");
    }

    private static void LoadOrCreateConfiguration()
    {
        try
        {
            logger.Debug("Checking if configuration file exists...");
            var directory = Path.GetDirectoryName(ConfigFilePath);

            if (!string.IsNullOrWhiteSpace(directory))
            {
                logger.Debug($"Ensuring directory exists: {directory}");
                Directory.CreateDirectory(directory);
            }

            if (!File.Exists(ConfigFilePath))
            {
                logger.Info("Configuration file does not exist. Creating default configuration...");
                CreateConfiguration();
                return;
            }

            logger.Info("Loading configuration from file...");
            var parser = new FileIniDataParser();
            var configData = parser.ReadFile(ConfigFilePath);

            foreach (var section in configData.Sections)
            {
                if (_configStructure.ContainsKey(section.SectionName))
                {
                    foreach (var key in section.Keys)
                    {
                        if (_configStructure[section.SectionName].ContainsKey(key.KeyName))
                        {
                            var existingEntry = _configStructure[section.SectionName][key.KeyName];
                            _configStructure[section.SectionName][key.KeyName] = (key.Value, existingEntry.Comment);
                        }
                    }
                }
            }

            logger.Info("Configuration loaded successfully.");
        }
        catch (Exception ex)
        {
            logger.Error($"Error loading configuration: {ex.Message}");
            CreateConfiguration();
        }
    }

    private static void CreateConfiguration()
    {
        try
        {
            logger.Info("Creating default configuration file...");

            using (var writer = new StreamWriter(ConfigFilePath))
            {
                foreach (var section in _configStructure)
                {
                    writer.WriteLine($"[{section.Key}]");
                    foreach (var setting in section.Value)
                    {
                        writer.WriteLine($"; {setting.Value.Comment}");
                        writer.WriteLine($"{setting.Key}={setting.Value.Value}");
                    }
                    writer.WriteLine();
                }
            }

            logger.Info("Default configuration file created.");
        }
        catch (Exception ex)
        {
            logger.Error($"Error creating configuration file: {ex.Message}");
        }
    }

    public static string GetValue(string section, string key)
    {
        logger.Debug($"Fetching value for {section}.{key}...");
        if (_configStructure.TryGetValue(section, out var sectionDict) &&
            sectionDict.TryGetValue(key, out var value))
        {
            logger.Debug($"Value found: {value.Value}");
            return value.Value;
        }

        logger.Error($"Configuration key not found: {section}.{key}");
        throw new KeyNotFoundException($"Configuration key not found: {section}.{key}");
    }

    public static void UpdateValue(string section, string key, string value)
    {
        logger.Debug($"Updating configuration value for {section}.{key}...");

        if (!_configStructure.ContainsKey(section) || !_configStructure[section].ContainsKey(key))
        {
            logger.Error($"Configuration key not found: {section}.{key}");
            throw new KeyNotFoundException($"Configuration key not found: {section}.{key}");
        }

        var existingEntry = _configStructure[section][key];
        _configStructure[section][key] = (value, existingEntry.Comment);

        try
        {
            var parser = new FileIniDataParser();
            var configData = parser.ReadFile(ConfigFilePath);

            configData.Sections[section][key] = value;
            parser.WriteFile(ConfigFilePath, configData);

            logger.Info($"Configuration value for {section}.{key} updated successfully.");
        }
        catch (Exception ex)
        {
            logger.Error($"Error updating configuration file: {ex.Message}");
        }
    }

    public static Dictionary<string, Dictionary<string, string>> GetAllConfigurations()
    {
        logger.Debug("Fetching all configurations...");
        return _configStructure.ToDictionary(
            section => section.Key,
            section => section.Value.ToDictionary(
                setting => setting.Key,
                setting => setting.Value.Value
            )
        );
    }
}