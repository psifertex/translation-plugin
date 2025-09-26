"""
Core translation functionality shared between render layer and symbol renaming
"""

import re
from binaryninja import Logger, Settings

log = Logger(session_id=0, logger_name="Translation")


class TranslationCache:
    """Singleton translation cache shared across all translation features"""
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(TranslationCache, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self._initialized = True
            self.cache = {}
            self.models = {}
            self.models_initialized = False
            self.alert_shown = False
            log.log_debug("Translation cache initialized")

    def _init_models(self):
        """Initialize translation models based on destination language"""
        if self.models_initialized:
            return

        self.models_initialized = True
        self.models = {}

        try:
            dest_lang = Settings().get_string("translation.destination_language")
            if not dest_lang or dest_lang == "None":
                log.log_warn("No destination language selected in settings")
                return

            import argostranslate.package

            installed_packages = argostranslate.package.get_installed_packages()
            for pkg in installed_packages:
                if pkg.to_code == dest_lang:
                    self.models[pkg.from_code] = pkg
                    log.log_debug(f"Loaded translation model: {pkg.from_code} -> {pkg.to_code}")

            if not self.models:
                log.log_warn(f"No translation models found for destination language '{dest_lang}'")
                log.log_warn(f"Install models with: argospm install translate-[source]_{dest_lang}")

        except ImportError:
            if not self.alert_shown:
                log.log_alert("Translation requires 'argostranslate' package. Install with: pip install argostranslate")
                self.alert_shown = True
        except Exception as e:
            log.log_error(f"Error initializing translation models: {e}")

    def get(self, text, source_lang=None):
        """Get translation from cache or perform new translation"""
        cache_key = f"{text}:{source_lang if source_lang else 'auto'}"
        if cache_key in self.cache:
            return self.cache[cache_key]

        if not self.models_initialized:
            self._init_models()
        if source_lang is None:
            source_lang = detect_language_argos(text, self.models)
            if source_lang:
                log.log_debug(f"Detected language '{source_lang}' for text: {repr(text)}")

        if source_lang and source_lang in self.models:
            translated = translate_text(text, source_lang, self.models[source_lang])
            log.log_debug(f"Translation: '{text}' -> '{translated}' (lang: {source_lang})")
            self.cache[cache_key] = translated
            return translated

        log.log_debug(f"No translation available for '{text}' (detected lang: {source_lang})")
        self.cache[cache_key] = text
        return text

    def get_clean(self, text, source_lang=None):
        """Get translation for use in symbol names (sanitized)"""
        translated = self.get(text, source_lang)
        if translated != text:
            return sanitize_name(translated)
        return None


PROGRAMMING_PREFIXES = [
    # Objective-C/Swift
    'sel_',           # Selector
    'ivar_',          # Instance variable
    'iVarName_',      # Instance variable name
    'clsName_',       # Class name
    'cls_',           # Class
    'prop_',          # Property
    'method_',        # Method
    'proto_',         # Protocol
    'cat_',           # Category

    # C/C++
    'vtable_',        # Virtual table
    'vptr_',          # Virtual pointer
    'ctor_',          # Constructor
    'dtor_',          # Destructor
    'lpfn_',          # Long pointer to function
    'pfn_',           # Pointer to function
    'cb_',            # Callback
    'lp_',            # Long pointer
    'p_',             # Pointer
    'pp_',            # Pointer to pointer
    'rg_',            # Range/array
    'c_',             # Count
    'n_',             # Number
    'sz_',            # Zero-terminated string
    'str_',           # String
    'psz_',           # Pointer to zero-terminated string
    'wsz_',           # Wide string zero-terminated

    # Windows/COM
    'IID_',           # Interface ID
    'CLSID_',         # Class ID
    'GUID_',          # Global unique ID
    'uuid_',          # Universal unique ID
    'riid_',          # Reference to interface ID
    'rclsid_',        # Reference to class ID

    # Python
    '__pyx_',         # Cython
    '__py_',          # Python internal
    '_Py_',           # Python C API

    # Go
    'go_',            # Go runtime
    'runtime_',       # Runtime functions

    # Rust
    'rs_',            # Rust
    '_ZN',            # Rust mangled name start

    # General
    'fn_',            # Function
    'func_',          # Function
    'sub_',           # Subroutine
    'loc_',           # Location
    'var_',           # Variable
    'arg_',           # Argument
    'param_',         # Parameter
    'ret_',           # Return value
    'tmp_',           # Temporary
    'temp_',          # Temporary
    'local_',         # Local variable
    'global_',        # Global variable
    'static_',        # Static
    'const_',         # Constant
    'enum_',          # Enumeration
    'struct_',        # Structure
    'union_',         # Union
    'type_',          # Type
    'typedef_',       # Type definition
    'ns_',            # Namespace
    'mod_',           # Module
]

def strip_programming_prefix(text):
    """Remove common programming prefixes for language detection/translation"""
    if not text:
        return text

    text_lower = text.lower()
    for prefix in PROGRAMMING_PREFIXES:
        if text_lower.startswith(prefix.lower()):
            return text[len(prefix):]

    return text

def detect_language_argos(text, models):
    """
    Detect source language based on available models and text content
    Returns the source language code if a model is available
    """
    if not text or not models:
        return None

    stripped_text = strip_programming_prefix(text)
    if not stripped_text:
        return None

    if 'ko' in models and detect_korean(stripped_text):
        return 'ko'

    if 'ja' in models and detect_japanese_specific(stripped_text):
        return 'ja'

    if 'zh' in models and detect_chinese(stripped_text):
        return 'zh'

    if 'ja' in models and 'zh' not in models and detect_japanese(stripped_text):
        return 'ja'

    if 'ru' in models and detect_cyrillic(stripped_text):
        return 'ru'

    if 'ar' in models and detect_arabic(stripped_text):
        return 'ar'

    return None


def detect_cyrillic(text):
    """Detect Cyrillic script (Russian, etc.)"""
    return bool(re.search(r'[\u0400-\u04FF]', text))


def detect_japanese_specific(text):
    """Detect Japanese-specific characters (Hiragana or Katakana)"""
    return bool(re.search(r'[\u3040-\u309F\u30A0-\u30FF]', text))

def detect_japanese(text):
    """Detect Japanese (Hiragana, Katakana, or Kanji)"""
    return bool(re.search(r'[\u3040-\u309F\u30A0-\u30FF\u4E00-\u9FAF]', text))


def detect_chinese(text):
    """Detect Chinese characters (excluding Japanese-specific ranges)"""
    has_cjk = bool(re.search(r'[\u4E00-\u9FFF\u3400-\u4DBF]', text))
    has_kana = bool(re.search(r'[\u3040-\u309F\u30A0-\u30FF]', text))

    has_simplified_chinese = bool(re.search(r'[你好世界们这那什么没有的了是我他她它]', text))

    return (has_cjk and not has_kana) or has_simplified_chinese


def detect_korean(text):
    """Detect Korean (Hangul)"""
    return bool(re.search(r'[\uAC00-\uD7AF\u1100-\u11FF\u3130-\u318F]', text))


def detect_arabic(text):
    """Detect Arabic script"""
    return bool(re.search(r'[\u0600-\u06FF\u0750-\u077F]', text))


def translate_text(text, source_lang, model):
    """
    Translate text using the provided model
    """
    try:
        import argostranslate.translate

        original_text = text
        stripped_text = strip_programming_prefix(text)
        if stripped_text != text:
            prefix = text[:len(text)-len(stripped_text)]
            log.log_debug(f"Stripped prefix '{prefix}' from '{text}'")

            log.log_debug(f"Calling argostranslate.translate with text='{stripped_text}', from={model.from_code}, to={model.to_code}")
            translated_part = argostranslate.translate.translate(stripped_text, model.from_code, model.to_code)
            log.log_debug(f"Argostranslate returned: '{translated_part}'")

            result = prefix + translated_part
            return result
        else:
            log.log_debug(f"Calling argostranslate.translate with text='{text}', from={model.from_code}, to={model.to_code}")
            result = argostranslate.translate.translate(text, model.from_code, model.to_code)
            log.log_debug(f"Argostranslate returned: '{result}'")
            return result

    except Exception as e:
        log.log_error(f"Translation failed for '{text}': {e}")
        import traceback
        log.log_debug(traceback.format_exc())
        return text


def sanitize_name(name):
    """
    Sanitize translated text to be a valid function/variable name
    """
    name = name.replace(' ', '_')
    name = re.sub(r'[^a-zA-Z0-9_]', '', name)

    if name and not name[0].isalpha() and name[0] != '_':
        name = '_' + name

    if len(name) > 64:
        name = name[:64]

    return name if name else None