"""Pure, bounded source-change summaries for private backup indexes.

Only line ranges and symbol names are returned; source text is never included.
Python symbols use the AST. C# symbols use an explicitly best-effort scanner.
"""
from __future__ import annotations

import ast
import bisect
import difflib
from pathlib import PurePosixPath
import re


SOURCE_EXTENSIONS = frozenset({
    '.cs', '.py', '.pyw', '.ps1', '.psm1', '.c', '.cc', '.cpp', '.cxx',
    '.h', '.hh', '.hpp', '.hxx', '.js', '.jsx', '.ts', '.tsx', '.lua',
    '.go', '.rs', '.java', '.kt', '.swift', '.rb', '.sh', '.bash', '.bat', '.cmd',
})
MAX_BYTES = 2 * 1024 * 1024
MAX_LINES = 20_000
MAX_DIFF_PRODUCT = 4_000_000
MAX_ITEMS = 12


def is_source(name: str) -> bool:
    path = PurePosixPath(name.replace('\\', '/'))
    return ('docs' not in {part.casefold() for part in path.parts}
            and path.suffix.casefold() in SOURCE_EXTENSIONS)


def _decode(data: bytes | None) -> tuple[str, str]:
    if data is None:
        return '', ''
    if len(data) > MAX_BYTES:
        return '', 'file exceeds 2 MiB limit'
    try:
        encoding = 'utf-16' if data.startswith((b'\xff\xfe', b'\xfe\xff')) else 'utf-8-sig'
        text = data.decode(encoding)
    except UnicodeError:
        return '', 'unsupported encoding'
    if any(ord(char) < 32 and char not in '\r\n\t\f' for char in text):
        return '', 'binary/control bytes'
    if len(text.splitlines()) > MAX_LINES:
        return '', 'file exceeds 20000-line limit'
    return text.replace('\r\n', '\n').replace('\r', '\n'), ''


def _limited(values: list[str]) -> str:
    values = list(dict.fromkeys(values))
    shown = ', '.join(values[:MAX_ITEMS])
    return shown + (f', +{len(values) - MAX_ITEMS} more' if len(values) > MAX_ITEMS else '')


def _ranges(spans: list[tuple[int, int]], data: bytes | None, lines: list[str]) -> str:
    if data is None:
        return 'absent'
    if not lines:
        return 'empty'
    values = []
    for start, end in spans:
        if start == end:
            values.append('- (before line 1)' if not start else f'- (after line {start})')
        else:
            values.append(str(start + 1) if end == start + 1 else f'{start + 1}-{end}')
    return _limited(values) or '-'


def _python_symbols(text: str) -> tuple[list[tuple[str, int, int]], str]:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return [], 'Python syntax unavailable'
    symbols = []

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.scope = []

        def visit_ClassDef(self, node):
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        def visit_FunctionDef(self, node):
            start = min([node.lineno, *(item.lineno for item in node.decorator_list)])
            symbols.append(('.'.join([*self.scope, node.name]), start, node.end_lineno))
            self.scope.append(node.name)
            self.generic_visit(node)
            self.scope.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

    try:
        Visitor().visit(tree)
    except RecursionError:
        return [], 'Python nesting limit'
    return symbols, ''


def _pair_ends(text: str) -> tuple[dict[int, int], bool]:
    stacks = {char: [] for char in '({['}
    closing = dict(zip(')}]', '({['))
    pairs, complete = {}, True
    for index, char in enumerate(text):
        if char in stacks:
            stacks[char].append(index)
        elif char in closing:
            stack = stacks[closing[char]]
            if stack:
                pairs[stack.pop()] = index + 1
            else:
                complete = False
    return pairs, complete and not any(stacks.values())


def _mask_csharp(text: str) -> str:
    """Mask literals/comments, retaining every position and physical newline."""
    result = list(text)
    length = len(text)

    def blank(start, end):
        for index in range(start, end):
            if result[index] not in '\r\n':
                result[index] = ' '

    def token_end(start, depth=0):
        if depth > 64:
            raise ValueError('C# literal nesting limit')
        if text.startswith('//', start):
            end = text.find('\n', start + 2)
            return length if end < 0 else end
        if text.startswith('/*', start):
            end = text.find('*/', start + 2)
            if end < 0:
                raise ValueError('unterminated C# comment')
            return end + 2
        index = start
        while index < length and text[index] in '$@':
            index += 1
        prefix = text[start:index]
        if index >= length or text[index] not in '\"\'':
            return None
        quote = text[index]
        if quote == "'" and prefix:
            return None
        quote_count = 1
        if quote == '"':
            while index + quote_count < length and text[index + quote_count] == '"':
                quote_count += 1
        if quote_count >= 3:
            end = text.find('"' * quote_count, index + quote_count)
            if end < 0:
                raise ValueError('unterminated C# raw string')
            return end + quote_count
        index += 1
        verbatim, interpolated = '@' in prefix, '$' in prefix
        while index < length:
            char = text[index]
            if char == quote:
                if verbatim and index + 1 < length and text[index + 1] == quote:
                    index += 2
                    continue
                return index + 1
            if char == '\\' and not verbatim:
                index += 2
                continue
            if interpolated and char == '{':
                if text.startswith('{{', index):
                    index += 2
                    continue
                level = 1
                index += 1
                while index < length and level:
                    end = token_end(index, depth + 1)
                    if end is not None:
                        index = end
                        continue
                    level += (text[index] == '{') - (text[index] == '}')
                    index += 1
                if level:
                    raise ValueError('unterminated C# interpolation')
                continue
            index += 1
        raise ValueError('unterminated C# literal')

    index = 0
    while index < length:
        end = token_end(index)
        if end is None:
            index += 1
        else:
            blank(index, end)
            index = end
    return ''.join(result)


def _csharp_symbols(text: str) -> tuple[list[tuple[str, int, int]], str]:
    """Recognize common declarations; this is a navigation aid, not a C# parser."""
    try:
        masked = _mask_csharp(text)
    except (ValueError, RecursionError) as error:
        return [], str(error) or 'C# structure unavailable'
    pairs, complete = _pair_ends(masked)
    attributes = []
    chars = list(masked)
    for match in re.finditer(r'(?m)^[ \t]*\[', masked):
        start = match.end() - 1
        while start < len(masked) and masked[start] == '[':
            end = pairs.get(start)
            if end is None:
                return [], 'C# attribute structure unavailable'
            attributes.append((start, end))
            for index in range(start, end):
                if chars[index] not in '\r\n':
                    chars[index] = ' '
            start = end
            while start < len(masked) and masked[start].isspace():
                start += 1
    code = ''.join(chars)
    newlines = [match.start() for match in re.finditer('\n', text)]
    line = lambda offset: bisect.bisect_right(newlines, offset) + 1
    types = []
    for match in re.finditer(r'\b(?:class|struct|interface|record(?:\s+(?:class|struct))?)\s+(\w+)[^;{}]*\{', code):
        end = pairs.get(match.end() - 1)
        if end is not None:
            types.append((match.group(1), match.start(), end))
    records = []
    note = '' if complete else 'some C# declarations unrecognized'
    control = re.compile(r'^(?:if|else|for|foreach|while|switch|catch|using|lock|return|throw|await|new|case|class|struct|record|interface|namespace|delegate)\b')
    name_pattern = re.compile(r'(?P<name>~?@?[A-Za-z_]\w*(?:\s*<[^;{}()\r\n]*>)?(?:\s*\.\s*@?[A-Za-z_]\w*(?:\s*<[^;{}()\r\n]*>)?)*)$')
    tail_pattern = re.compile(r'\s*(?:(?:where\b|:)\s*[^;{}=]*?)?(?P<body>\{|=>|;)')
    for match in re.finditer(r'(?m)^[ \t]*(?P<head>[^\n;{}=]+?)\(', code):
        head = match.group('head').strip()
        if control.match(head):
            continue
        named = name_pattern.search(head)
        if named is None:
            continue
        declaration_prefix = head[:named.start()].strip()
        # Continuations such as "&& Helper.Ready();" are calls, not typed members.
        # Keep ordinary modifiers, qualified/generic/nullable/pointer return types.
        if declaration_prefix and (not re.fullmatch(r'[\w@<>,.?\[\]:*\s]+', declaration_prefix)
                                   or not re.match(r'[@A-Za-z_]', declaration_prefix)):
            continue
        name = re.sub(r'\s+', '', named.group('name'))
        if name in {'get', 'set', 'init', 'nameof', 'typeof', 'sizeof', 'checked', 'unchecked'}:
            continue
        close = pairs.get(match.end() - 1)
        if close is None:
            note = 'some C# declarations unrecognized'
            continue
        tail = tail_pattern.match(code, close)
        if tail is None:
            continue
        kind = tail.group('body')
        # A bare call ending in ';' is not an abstract/interface declaration.
        if kind == ';' and not declaration_prefix:
            continue
        body = tail.start('body')
        if kind == '{':
            end = pairs.get(body)
        elif kind == '=>':
            cursor, levels = body + 2, 0
            while cursor < len(code):
                char = code[cursor]
                if char == ';' and not levels:
                    break
                levels += (char in '({[') - (char in ')}]')
                cursor += 1
            end = cursor + 1 if cursor < len(code) else None
        else:
            end = body + 1
        if end is None:
            note = 'some C# declarations unrecognized'
            continue
        start = match.start('head')
        while start < len(code) and code[start].isspace():
            start += 1
        for attr_start, attr_end in reversed(attributes):
            if attr_end <= start and not code[attr_end:start].strip():
                start = attr_start
        owner = [item[0] for item in types if item[1] <= start < item[2]]
        records.append(('.'.join([*owner, name]), line(start), line(end - 1)))
    return records, note


def _functions(suffix: str, old_text: str, new_text: str, changes: list[tuple[int, int, int, int]]) -> str:
    if suffix not in {'.py', '.pyw', '.cs'}:
        return 'functions unavailable (unsupported language)'
    extract = _csharp_symbols if suffix == '.cs' else _python_symbols
    names, notes = [], []
    for side, text, offset in (('old', old_text, 0), ('new', new_text, 2)):
        symbols, note = extract(text)
        if note:
            notes.append(side + ': ' + note)
        for name, start, end in symbols:
            if any(change[offset] < change[offset + 1]
                   and start <= change[offset + 1] and end > change[offset] for change in changes):
                names.append(name)
    label = 'functions (C# best effort)' if suffix == '.cs' else 'functions'
    if names:
        result = label + ' ' + _limited(names)
    elif notes:
        result = label + ' unavailable'
    else:
        result = label + ' none (outside recognized function)'
    if notes:
        result += '; ' + '; '.join(notes)
    return result


def analyze_change(name: str, old: bytes | None, new: bytes | None) -> str:
    """Describe changed line ranges and affected symbols without source excerpts."""
    if not is_source(name):
        return 'lines/functions unavailable (unsupported source type)'
    old_text, old_error = _decode(old)
    new_text, new_error = _decode(new)
    errors = [side + ': ' + error for side, error in (('old', old_error), ('new', new_error)) if error]
    if errors:
        return 'lines/functions unavailable (' + '; '.join(errors) + ')'
    old_lines, new_lines = old_text.splitlines(), new_text.splitlines()
    if old_lines == new_lines:
        if old == new:
            reason = 'unchanged'
        elif old is None or new is None:
            reason = 'empty source file'
        else:
            reason = 'line endings/encoding only'
        return (f'old {_ranges([], old, old_lines)} -> new {_ranges([], new, new_lines)} '
                f'| functions none ({reason})')
    prefix = 0
    while prefix < min(len(old_lines), len(new_lines)) and old_lines[prefix] == new_lines[prefix]:
        prefix += 1
    old_end, new_end = len(old_lines), len(new_lines)
    while old_end > prefix and new_end > prefix and old_lines[old_end - 1] == new_lines[new_end - 1]:
        old_end -= 1
        new_end -= 1
    limited = (old_end - prefix) * (new_end - prefix) > MAX_DIFF_PRODUCT
    if limited:
        changes = [(prefix, old_end, prefix, new_end)]
    else:
        matcher = difflib.SequenceMatcher(None, old_lines[prefix:old_end], new_lines[prefix:new_end], autojunk=False)
        changes = [(i1 + prefix, i2 + prefix, j1 + prefix, j2 + prefix)
                   for tag, i1, i2, j1, j2 in matcher.get_opcodes() if tag != 'equal']
    old_spans = [(item[0], item[1]) for item in changes]
    new_spans = [(item[2], item[3]) for item in changes]
    result = (f'old {_ranges(old_spans, old, old_lines)} -> new {_ranges(new_spans, new, new_lines)} '
              '| ' + _functions(PurePosixPath(name).suffix.casefold(), old_text, new_text, changes))
    if limited:
        result += ' | coarse changed-region ranges/functions (diff limit)'
    return result
