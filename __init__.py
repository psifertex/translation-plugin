"""
Translation Plugin for Binary Ninja
"""

# Suppress PyTorch/stanza warnings about weights_only=False
# These will be resolved whenever argos does a new release:
#   https://github.com/argosopentech/argos-translate/issues/439#issuecomment-3330959528
import warnings
warnings.filterwarnings("ignore", message=".*weights_only=False.*", category=FutureWarning)
warnings.filterwarnings("ignore", message=".*torch.load.*", category=FutureWarning)

from . import settings
from .render_layer import TranslateRenderLayer
from .symbol_renamer import TranslateSymbolRenamer, SymbolRenamerThread
from binaryninja import PluginCommand, Settings, Symbol, interaction
from .translation_core import log, TranslationCache

TranslateRenderLayer.register()
def translate_symbols_command(bv):
    """Manually trigger symbol translation"""
    log.log_info("Manual symbol translation triggered")
    try:
        dest_lang = Settings().get_string("translation.destination_language")
        if dest_lang and dest_lang != "None":
            thread = SymbolRenamerThread(bv)
            thread.start()
        else:
            log.log_info("No destination language selected")
    except Exception as e:
        log.log_error(f"Error checking destination language: {e}")
def translate_single_symbol(bv, addr):
    """Translate a single symbol at the current location"""
    log.log_info("Single symbol translation triggered")

    try:
        dest_lang = Settings().get_string("translation.destination_language")
        if not dest_lang or dest_lang == "None":
            log.log_info("No destination language selected")
            return
    except Exception as e:
        log.log_error(f"Error checking destination language: {e}")
        return

    symbol = bv.get_symbol_at(addr)
    func = bv.get_function_at(addr)

    if not symbol and func:
        symbol = func.symbol

    if not symbol:
        log.log_info("No symbol found at current address")
        return

    cache = TranslationCache()

    translated = cache.get_clean(symbol.name)
    if translated:
        try:
            prefix = Settings().get_string("translation.rename_prefix")
        except:
            prefix = "🌎 "

        if prefix:
            translated = prefix + translated

        if func:
            func.name = translated
            log.log_info(f"Translated function: {symbol.name} -> {translated}")
        else:
            bv.define_user_symbol(Symbol(symbol.type, addr, translated))
            log.log_info(f"Translated symbol: {symbol.name} -> {translated}")
    else:
        log.log_info(f"No translation available for: {symbol.name}")
def add_string_translation_comments(bv):
    """Add translation comments to all strings in the binary"""
    log.log_info("Adding translation comments to strings")

    try:
        dest_lang = Settings().get_string("translation.destination_language")
        if not dest_lang or dest_lang == "None":
            log.log_info("No destination language selected")
            return
    except Exception as e:
        log.log_error(f"Error checking destination language: {e}")
        return

    cache = TranslationCache()
    comment_count = 0
    skipped_count = 0

    for string_ref in bv.strings:
        try:
            string_value = string_ref.value if hasattr(string_ref, 'value') else None
            if not string_value:
                skipped_count += 1
                continue

            if '�' in string_value:
                skipped_count += 1
                continue

            translated = cache.get(string_value)
            if translated and translated != string_value:
                try:
                    prefix = Settings().get_string("translation.rename_prefix")
                except:
                    prefix = "🌎 "

                if prefix:
                    translated = prefix + translated

                refs = bv.get_code_refs(string_ref.start)

                for ref in refs:
                    existing_comment = bv.get_comment_at(ref.address)
                    if existing_comment and translated in existing_comment:
                        continue

                    if existing_comment:
                        new_comment = f"{existing_comment} | {translated}"
                    else:
                        new_comment = translated

                    bv.set_comment_at(ref.address, new_comment)
                    comment_count += 1
                    log.log_debug(f"Added comment at {ref.address:#x}: {translated}")

                existing_comment = bv.get_comment_at(string_ref.start)
                if not (existing_comment and translated in existing_comment):
                    if existing_comment:
                        new_comment = f"{existing_comment} | {translated}"
                    else:
                        new_comment = translated

                    bv.set_comment_at(string_ref.start, new_comment)
                    comment_count += 1
                    log.log_debug(f"Added comment at string {string_ref.start:#x}: {translated}")
            else:
                skipped_count += 1

        except Exception as e:
            log.log_debug(f"Error processing string at {string_ref.start:#x}: {e}")
            skipped_count += 1

    log.log_info(f"String translation comments complete: {comment_count} comments added, {skipped_count} strings skipped")

PluginCommand.register(
    "Translate\\Translate All Symbols",
    "Translate all foreign language symbols in the binary",
    translate_symbols_command
)

PluginCommand.register_for_address(
    "Translate\\Translate Current Symbol",
    "Translate the symbol at the current address",
    translate_single_symbol
)

PluginCommand.register(
    "Translate\\Add String Translation Comments",
    "Add translation comments to all string references",
    add_string_translation_comments
)

__all__ = ['TranslateRenderLayer']