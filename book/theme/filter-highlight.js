// Syntax highlighting for ```filter blocks (Wireshark display filters with Avulse extensions).
// mdBook highlights code before this script runs, so the filter blocks are highlighted again here.
(function () {
    "use strict";
    if (typeof hljs === "undefined") {
        return;
    }
    hljs.registerLanguage("filter", function (hljs) {
        return {
            name: "Avulse filter",
            keywords: {
                $pattern: /[A-Za-z_]+/,
                keyword:
                    "and or not xor in contains matches let any all eq ne lt le gt ge " +
                    "any_eq all_ne all_eq any_ne AND OR NOT XOR",
                literal: "true false",
                built_in: "len count max min abs upper lower",
            },
            contains: [
                // `#` followed by a digit or `[` is the layer operator, not a comment.
                { className: "comment", begin: /#(?![\d[])/, end: /$/ },
                hljs.C_LINE_COMMENT_MODE,
                hljs.C_BLOCK_COMMENT_MODE,
                { className: "string", begin: /r"/, end: /"/ },
                { className: "string", begin: /"/, end: /"/, contains: [hljs.BACKSLASH_ESCAPE] },
                { className: "string", begin: /'/, end: /'/, contains: [hljs.BACKSLASH_ESCAPE] },
                { className: "variable", begin: /\$\{?[A-Za-z_]\w*\}?/ },
                { className: "meta", begin: /#\[[^\]]*\]|#-?\d+/ },
                { className: "attr", begin: /@?\.?[a-z][\w-]*(?:\.[a-z_][\w-]*)+/ },
                { className: "number", begin: /\b\d{1,3}(?:\.\d{1,3}){3}(?:\/\d+)?/ },
                { className: "number", begin: /\b[0-9a-fA-F]{0,4}(?:::?[0-9a-fA-F]{1,4})+::?(?:\/\d+)?|::[0-9a-fA-F]*(?:\/\d+)?/ },
                { className: "number", begin: /\b[0-9a-fA-F]{2}(?:[:.-][0-9a-fA-F]{2})+\b|\b[0-9a-fA-F]{2}:/ },
                { className: "number", begin: /\b0x[0-9a-fA-F]+\b|\b\d+\b/ },
            ],
        };
    });
    document.querySelectorAll("code.language-filter").forEach(function (block) {
        block.textContent = block.textContent;
        hljs.highlightBlock(block);
    });
})();
