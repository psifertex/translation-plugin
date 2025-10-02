"""
Render layer for replacing foreign text with translations in disassembly views
"""

from binaryninja import RenderLayer, RenderLayerDefaultEnableState, BasicBlock, \
    InstructionTextTokenType, InstructionTextToken, Settings, \
    DisassemblyTextLine
from .translation_core import TranslationCache, detect_language_argos, log


class TranslateRenderLayer(RenderLayer):
    name = "Translation"
    default_enable_state = RenderLayerDefaultEnableState.DisabledByDefaultRenderLayerDefaultEnableState

    def __init__(self):
        super().__init__()
        self.cache = TranslationCache()
        log.log_debug("TranslateRenderLayer initialized")

    def _get_rename_prefix(self):
        """Get the prefix to add to translated text"""
        return Settings().get_string("translation.rename_prefix")

    def _get_current_settings(self):
        """Get current source and destination language settings"""
        source_lang = Settings().get_string("translation.source_language")
        dest_lang = Settings().get_string("translation.destination_language")
        return source_lang, dest_lang

    def _should_process(self):
        """Check if render layer should process based on destination language setting"""
        _, dest_lang = self._get_current_settings()

        should_process = dest_lang and dest_lang != "None"
        if should_process:
            log.log_debug(f"Render layer processing enabled for language: {dest_lang}")
        else:
            log.log_debug("No destination language selected, render layer inactive")
        return should_process

    def _replace_token_text(self, token, translated_text):
        """Create a new token with replaced text"""
        return InstructionTextToken(
            token.type,
            translated_text,
            token.value,
            token.size,
            token.operand,
            token.confidence,
            token.address
        )

    def apply_to_linear_view_object(self, obj, prev, next, lines):
        """Apply translations to Linear View"""
        log.log_debug(f"apply_to_linear_view_object called with {len(lines)} lines")

        if not self._should_process():
            return lines

        try:
            for line in lines:
                if hasattr(line, 'contents') and line.contents:
                    contents = line.contents
                    if hasattr(contents, 'tokens') and contents.tokens:
                        for i, token in enumerate(contents.tokens):
                            try:
                                if hasattr(token, 'text') and token.text:
                                    if '�' not in token.text:
                                        if token.type in [InstructionTextTokenType.StringToken,
                                                        InstructionTextTokenType.CodeSymbolToken,
                                                        InstructionTextTokenType.DataSymbolToken,
                                                        InstructionTextTokenType.ImportToken]:

                                            log.log_debug(f"Processing token text: {repr(token.text)}, type: {token.type}")
                                            translated = self.cache.get(token.text)
                                            if translated != token.text:
                                                prefix = self._get_rename_prefix()
                                                if prefix:
                                                    translated = prefix + translated
                                                contents.tokens[i] = self._replace_token_text(token, translated)
                                                log.log_debug(f"Replaced '{token.text}' with '{translated}'")

                            except Exception as e:
                                log.log_debug(f"Error processing token: {e}")

            return lines

        except Exception as e:
            log.log_error(f"Error in apply_to_linear_view_object: {e}")
            import traceback
            log.log_debug(traceback.format_exc())
            return lines

    def apply_to_disassembly_block(self, block, lines):
        """Apply translations to disassembly/graph view"""
        log.log_debug(f"apply_to_disassembly_block called with {len(lines)} lines")

        if not self._should_process():
            return lines

        try:
            for line in lines:
                if hasattr(line, 'tokens') and line.tokens:
                    for i, token in enumerate(line.tokens):
                        try:
                            if hasattr(token, 'text') and token.text and '�' not in token.text:
                                if token.type in [InstructionTextTokenType.StringToken,
                                                InstructionTextTokenType.CodeSymbolToken,
                                                InstructionTextTokenType.DataSymbolToken,
                                                InstructionTextTokenType.ImportToken]:

                                    log.log_debug(f"Processing token text: {repr(token.text)}, type: {token.type}")
                                    translated = self.cache.get(token.text)
                                    if translated != token.text:
                                        prefix = self._get_rename_prefix()
                                        if prefix:
                                            translated = prefix + translated
                                        line.tokens[i] = self._replace_token_text(token, translated)
                                        log.log_debug(f"Replaced '{token.text}' with '{translated}'")

                        except Exception as e:
                            log.log_debug(f"Error processing token: {e}")

            return lines

        except Exception as e:
            log.log_error(f"Error in apply_to_disassembly_block: {e}")
            return lines

    def apply_to_high_level_il_body(self, function, lines):
        """Apply translations to High Level IL view"""
        log.log_debug(f"apply_to_high_level_il_body called with {len(lines)} lines")

        if not self._should_process():
            return lines

        try:
            for line in lines:
                if hasattr(line, 'tokens') and line.tokens:
                    for i, token in enumerate(line.tokens):
                        try:
                            if hasattr(token, 'text') and token.text and '�' not in token.text:
                                if token.type in [InstructionTextTokenType.StringToken,
                                                InstructionTextTokenType.CodeSymbolToken,
                                                InstructionTextTokenType.DataSymbolToken,
                                                InstructionTextTokenType.ImportToken]:

                                    log.log_debug(f"Processing token text: {repr(token.text)}, type: {token.type}")
                                    translated = self.cache.get(token.text)
                                    if translated != token.text:
                                        prefix = self._get_rename_prefix()
                                        if prefix:
                                            translated = prefix + translated
                                        line.tokens[i] = self._replace_token_text(token, translated)
                                        log.log_debug(f"Replaced '{token.text}' with '{translated}'")

                        except Exception as e:
                            log.log_debug(f"Error processing token: {e}")

            return lines

        except Exception as e:
            log.log_error(f"Error in apply_to_high_level_il_body: {e}")
            return lines

    def apply_to_misc_linear_lines(self, obj, prev, next, lines):
        """Apply translations to miscellaneous linear view lines (strings, etc.)"""
        log.log_debug(f"apply_to_misc_linear_lines called with {len(lines)} lines")

        if not self._should_process():
            return lines

        try:
            for line in lines:
                if hasattr(line, 'contents') and line.contents:
                    contents = line.contents
                    if hasattr(contents, 'tokens') and contents.tokens:
                        for i, token in enumerate(contents.tokens):
                            try:
                                if hasattr(token, 'text') and token.text:
                                    if '�' not in token.text:
                                        if token.type in [InstructionTextTokenType.StringToken,
                                                        InstructionTextTokenType.CodeSymbolToken,
                                                        InstructionTextTokenType.DataSymbolToken,
                                                        InstructionTextTokenType.ImportToken]:

                                            log.log_debug(f"Processing token text: {repr(token.text)}, type: {token.type}")
                                            translated = self.cache.get(token.text)
                                            if translated != token.text:
                                                prefix = self._get_rename_prefix()
                                                if prefix:
                                                    translated = prefix + translated
                                                contents.tokens[i] = self._replace_token_text(token, translated)
                                                log.log_debug(f"Replaced '{token.text}' with '{translated}'")

                            except Exception as e:
                                log.log_debug(f"Error processing token: {e}")

            return lines

        except Exception as e:
            log.log_error(f"Error in apply_to_misc_linear_lines: {e}")
            import traceback
            log.log_debug(traceback.format_exc())
            return lines