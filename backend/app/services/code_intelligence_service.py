
from tree_sitter_language_pack import detect_language_from_path, get_parser


class CodeIntelligenceError(Exception):
    pass


class CodeIntelligenceService:
    MAX_FILE_SIZE = 200_000
    MAX_NODES = 10_000
    MAX_ITEMS = 200

    FUNCTION_TYPES = {
        "function_definition",
        "function_declaration",
        "method_definition",
        "method_declaration",
        "function_item",
    }

    CLASS_TYPES = {
        "class_definition",
        "class_declaration",
        "class_specifier",
        "struct_item",
        "interface_declaration",
        "enum_declaration",
    }

    IMPORT_TYPES = {
        "import_statement",
        "import_from_statement",
        "import_declaration",
        "use_declaration",
        "preproc_include",
        "extern_crate_declaration",
    }

    NAME_TYPES = {
        "identifier",
        "type_identifier",
        "property_identifier",
        "constant",
    }

    def analyze_file(self, path: str, content: str) -> dict:
        language = detect_language_from_path(path)

        if language is None:
            return {
                "path": path,
                "language": None,
                "supported": False,
                "has_syntax_errors": False,
                "functions": [],
                "classes": [],
                "imports": [],
                "nodes_visited": 0,
                "truncated": False,
            }

        source = content.encode("utf-8")

        if len(source) > self.MAX_FILE_SIZE:
            raise CodeIntelligenceError("File exceeds size limit")

        try:
            parser = get_parser(language)
            tree = parser.parse(source)

            if tree is None:
                raise CodeIntelligenceError("Parsing failed")

            root = tree.root_node

            functions = []
            classes = []
            imports = []

            stack = [root]
            nodes_visited = 0
            truncated = False

            while stack:
                node = stack.pop()
                nodes_visited += 1

                if nodes_visited > self.MAX_NODES:
                    truncated = True
                    break

                node_type = node.type
                start_line = node.start_point.row + 1
                end_line = node.end_point.row + 1

                if node_type in self.FUNCTION_TYPES:
                    functions.append({
                        "name": self._get_name(node, source),
                        "line_start": start_line,
                        "line_end": end_line,
                    })

                elif node_type in self.CLASS_TYPES:
                    classes.append({
                        "name": self._get_name(node, source),
                        "line_start": start_line,
                        "line_end": end_line,
                    })

                elif node_type in self.IMPORT_TYPES:
                    text = source[node.start_byte:node.end_byte].decode(
                        "utf-8", errors="replace"
                    )

                    imports.append({
                        "text": " ".join(text.split())[:300],
                        "line": start_line,
                    })

                if (
                    len(functions) >= self.MAX_ITEMS
                    or len(classes) >= self.MAX_ITEMS
                    or len(imports) >= self.MAX_ITEMS
                ):
                    truncated = True
                    break

                stack.extend(reversed(node.children))

            return {
                "path": path,
                "language": language,
                "supported": True,
                "has_syntax_errors": root.has_error,
                "functions": functions,
                "classes": classes,
                "imports": imports,
                "nodes_visited": nodes_visited,
                "truncated": truncated,
            }

        except CodeIntelligenceError:
            raise
        except Exception as exc:
            raise CodeIntelligenceError(
                f"Unable to analyse {path}: {type(exc).__name__}"
            ) from exc

    def _get_name(self, node, source: bytes) -> str:
        for child in node.children:
            if child.type in self.NAME_TYPES:
                return source[
                    child.start_byte:child.end_byte
                ].decode("utf-8", errors="replace")

        return "anonymous"


code_intelligence_service = CodeIntelligenceService()
