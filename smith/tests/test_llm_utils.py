"""Tests for llm_utils.py — _extract_text content parsing."""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from llm_utils import _extract_text


class TestExtractText:
    def test_plain_string(self):
        assert _extract_text('hello') == 'hello'

    def test_empty_string(self):
        assert _extract_text('') == ''

    def test_content_blocks_list(self):
        content = [{'text': 'Hello ', 'type': 'text', 'index': 0},
                   {'text': 'world', 'type': 'text', 'index': 1}]
        assert _extract_text(content) == 'Hello world'

    def test_single_content_block(self):
        content = [{'text': 'Only block', 'type': 'text', 'index': 0}]
        assert _extract_text(content) == 'Only block'

    def test_mixed_list_with_strings(self):
        content = ['hello', ' ', 'world']
        assert _extract_text(content) == 'hello world'

    def test_empty_list(self):
        assert _extract_text([]) == ''

    def test_non_text_blocks_ignored(self):
        content = [{'text': 'visible', 'type': 'text', 'index': 0},
                   {'type': 'tool_use', 'id': 'x', 'name': 'foo'}]
        assert _extract_text(content) == 'visible'

    def test_block_missing_text_key(self):
        content = [{'type': 'text'}]
        assert _extract_text(content) == ''

    def test_fallback_for_other_types(self):
        assert _extract_text(42) == '42'
        assert _extract_text(None) == 'None'
