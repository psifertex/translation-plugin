# Translation Plugin for Binary Ninja

A plugin that translates foreign language text in binaries to any supported language using offline translation.

## IMPORTANT: Enable Correct Unicode Support Required

**This plugin requires Binary Ninja's Unicode support to be enabled to display non-ASCII characters in the appropriate codepages!**

**[Enable Unicode Support in Binary Ninja](https://docs.binary.ninja/dev/concepts.html?h=unicode#unicode-support)**

## Features

### Modes

1. **Real-time Translation (Render Layer)**
   - Replaces foreign text with translations directly in the disassembly view
   - Works in both Linear and Graph views
   - Non-destructive - original text preserved in database
   - Toggle on/off via View → Layer menu

Warning, this method can be slow!

2. **Manual Changes**
   - `Plugins` / `Translate` / `Translate All Symbols`
   - `Plugins` / `Translate` / `Translate Current Symbol`

Note that these changes will be made as user changes so saving them in an analysis database will persist.

3. **String Translation Comments**
   - Adds translation comments at string usage locations
   - Comments appear at both string definitions and references
   - Preserves existing comments


## Installation

### Step 1: Install the Plugin

#### Option A: Plugin Manager (Recommended)
Install from Binary Ninja's Plugin Manager - dependencies will be installed automatically.

#### Option B: Manual Installation
1. Clone or download this repository
2. Copy the `translate-layer` folder to your Binary Ninja plugins directory:
   - **macOS**: `~/Library/Application Support/Binary Ninja/plugins/`
   - **Linux**: `~/.binaryninja/plugins/`
   - **Windows**: `%APPDATA%\Binary Ninja\plugins\`
3. Restart Binary Ninja (it will automatically install the required Python packages)

### Step 2: Install Translation Models

The plugin uses [Argos Translate's](https://github.com/argosopentech/argos-translate) offline models. Install models for the language pairs you need:

```bash
# Update the package index
argospm update

# List available packages
argospm search

# Install language pairs (format: translate-[source]_[dest])
# Examples:
argospm install translate-ru_en    # Russian to English
argospm install translate-ja_en    # Japanese to English
argospm install translate-zh_en    # Chinese to English
argospm install translate-en_es    # English to Spanish
argospm install translate-fr_de    # French to German
```

## Configuration

Access settings via **Edit** → **Preferences** → **Settings** → **Translation**

Available settings:

- **Destination Language**: Target language for translations (based on installed models)
- **Translated Symbol Prefix**: Prefix for renamed symbols (default: "🌎")

## Supported Languages

The plugin can translate between any languages supported by Argos Translate models.

Check available models with `argospm search`.

## Troubleshooting

### No destination languages available
- Install translation models: `argospm install translate-[source]_[dest]`
- Restart Binary Ninja after installing models

### Manual dependency installation
If Binary Ninja doesn't automatically install dependencies:
```bash
pip install argostranslate
```

### Translations not appearing
- Check that a destination language is selected in settings
- Verify translation models are installed: `argospm list`
- Check the Binary Ninja log for error messages (enable debug logs for more information)

### Performance
- First translation after loading may be slow as models load
- Subsequent translations use the cache for instant results
