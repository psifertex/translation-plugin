"""
Automatic symbol renaming with translations after analysis completes
"""

from binaryninja import AnalysisCompletionEvent, BackgroundTaskThread, Settings
from .translation_core import TranslationCache, log


class TranslateSymbolRenamer:
    """Renames symbols with translations after analysis completes"""

    def __init__(self):
        self.cache = TranslationCache()
        log.log_debug("TranslateSymbolRenamer initialized")

    def _get_rename_prefix(self):
        """Get the prefix to add to renamed symbols"""
        return Settings().get_string("translation.rename_prefix")

    def rename_symbols(self, bv):
        """Rename all foreign language symbols in the binary view"""
        log.log_info(f"Starting symbol translation for {bv.file.filename}")
        renamed_count = 0
        skipped_count = 0
        for func in bv.functions:
            try:
                symbol = func.symbol
                if not symbol:
                    continue


                translated = self.cache.get_clean(symbol.name)
                if translated:
                    prefix = self._get_rename_prefix()
                    if prefix:
                        translated = prefix + translated

                    func.name = translated
                    renamed_count += 1
                    log.log_debug(f"Renamed function: {symbol.name} -> {translated}")

            except Exception as e:
                log.log_debug(f"Error renaming function {func.name}: {e}")

        for data_var in bv.data_vars:
            try:
                symbol = bv.get_symbol_at(data_var)
                if not symbol:
                    continue


                translated = self.cache.get_clean(symbol.name)
                if translated:
                    prefix = self._get_rename_prefix()
                    if prefix:
                        translated = prefix + translated

                    bv.define_user_symbol(bv.Symbol(symbol.type, data_var, translated))
                    renamed_count += 1
                    log.log_debug(f"Renamed data variable: {symbol.name} -> {translated}")

            except Exception as e:
                log.log_debug(f"Error renaming data variable at {data_var:#x}: {e}")

        for string in bv.strings:
            try:
                string_value = string.value if hasattr(string, 'value') else None
                if not string_value:
                    continue

                symbol = bv.get_symbol_at(string.start)
                if symbol:
                    translated = self.cache.get_clean(string_value[:50])
                    if translated:
                        prefix = self._get_rename_prefix()
                        translated = f"{prefix}str_{translated}" if prefix else f"str_{translated}"

                        bv.define_user_symbol(bv.Symbol(symbol.type, string.start, translated))
                        renamed_count += 1
                        log.log_debug(f"Renamed string: {symbol.name} -> {translated}")

            except Exception as e:
                log.log_debug(f"Error processing string at {string.start:#x}: {e}")

        log.log_info(f"Symbol translation complete: {renamed_count} renamed, {skipped_count} skipped")


class SymbolRenamerThread(BackgroundTaskThread):
    """Background thread for renaming symbols"""

    def __init__(self, bv):
        super().__init__(f"Translating symbols for {bv.file.filename}", True)
        self.bv = bv
        self.renamer = TranslateSymbolRenamer()

    def run(self):
        self.renamer.rename_symbols(self.bv)


