"""
Settings for the Translation plugin
"""

from binaryninja import Settings
from .translation_core import log

def get_available_languages():
    """Get list of available destination languages from installed models"""
    languages = ["None"]

    try:
        import argostranslate.package

        installed_packages = argostranslate.package.get_installed_packages()
        dest_langs = set()
        for pkg in installed_packages:
            dest_langs.add(pkg.to_code)

        if dest_langs:
            languages = sorted(list(dest_langs))
        else:
            log.log_warn("No translation models installed. Install with:\nargospm update\nargospm install translate-[source]_[dest]")

    except ImportError:
        log.log_warn("argostranslate not installed. Install with: pip install argostranslate")
    except Exception as e:
        log.log_debug(f"Error getting available languages: {e}")

    return languages

def get_available_source_languages():
    """Get list of available source languages from installed models"""
    languages = ["Auto"]

    try:
        import argostranslate.package

        installed_packages = argostranslate.package.get_installed_packages()
        source_langs = set()
        for pkg in installed_packages:
            source_langs.add(pkg.from_code)

        if source_langs:
            languages.extend(sorted(list(source_langs)))

    except ImportError:
        pass
    except Exception as e:
        log.log_debug(f"Error getting available source languages: {e}")

    return languages

Settings().register_group("translation", "Translation")

languages = get_available_languages()
source_languages = get_available_source_languages()
import json
Settings().register_setting(
    "translation.source_language",
    f"""
    {{
        "title": "Source Language",
        "type": "string",
        "default": "Auto",
        "enum": {json.dumps(source_languages)},
        "enumDescriptions": {json.dumps(source_languages)},
        "description": "Source language for translations (Auto = automatic detection)"
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
        "enumDescriptions": {json.dumps(languages)},
        "description": "Target language for translations (based on installed models)"
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
        "description": "Prefix to add to translated symbol names (empty for no prefix)"
    }
    """
)

