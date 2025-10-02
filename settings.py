"""
Settings for the Translation plugin
"""

from binaryninja import Settings
from .translation_core import log

def get_available_languages():
    """Get list of available destination languages from installed models"""
    languages = ["None"]
    descriptions = ["None"]

    try:
        import argostranslate.package

        installed_packages = argostranslate.package.get_installed_packages()
        dest_langs = {}
        for pkg in installed_packages:
            dest_langs[pkg.to_code] = pkg.to_name

        if dest_langs:
            sorted_codes = sorted(dest_langs.keys())
            languages = sorted_codes
            descriptions = [f"{dest_langs[code]} ({code})" for code in sorted_codes]
        else:
            log.log_warn("No translation models installed. Install with:\nargospm update\nargospm install translate-[source]_[dest]")

    except ImportError:
        log.log_warn("argostranslate not installed. Install with: pip install argostranslate")
    except Exception as e:
        log.log_debug(f"Error getting available languages: {e}")

    return languages, descriptions

def get_available_source_languages():
    """Get list of available source languages from installed models"""
    languages = ["Auto"]
    descriptions = ["Auto"]

    try:
        import argostranslate.package

        installed_packages = argostranslate.package.get_installed_packages()
        source_langs = {}
        for pkg in installed_packages:
            source_langs[pkg.from_code] = pkg.from_name

        if source_langs:
            sorted_codes = sorted(source_langs.keys())
            languages.extend(sorted_codes)
            descriptions.extend([f"{source_langs[code]} ({code})" for code in sorted_codes])

    except ImportError:
        pass
    except Exception as e:
        log.log_debug(f"Error getting available source languages: {e}")

    return languages, descriptions

Settings().register_group("translation", "Translation")

languages, language_descriptions = get_available_languages()
source_languages, source_descriptions = get_available_source_languages()
import json
Settings().register_setting(
    "translation.source_language",
    f"""
    {{
        "title": "Source Language",
        "type": "string",
        "default": "Auto",
        "enum": {json.dumps(source_languages)},
        "enumDescriptions": {json.dumps(source_descriptions)},
        "description": "Source language for translations (Auto = automatic detection)",
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }}
    """
)

Settings().register_setting(
    "translation.destination_language",
    f"""
    {{
        "title": "Destination Language",
        "type": "string",
        "default": "{languages[0] if languages else 'None'}",
        "enum": {json.dumps(languages)},
        "enumDescriptions": {json.dumps(language_descriptions)},
        "description": "Target language for translations (based on installed models)",
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }}
    """
)

Settings().register_setting(
    "translation.rename_prefix",
    """
    {
        "title": "Translated Symbol Prefix",
        "type": "string",
        "default": "🌎 ",
        "description": "Prefix to add to translated symbol names (empty for no prefix)",
        "ignore": ["SettingsProjectScope", "SettingsResourceScope"]
    }
    """
)

