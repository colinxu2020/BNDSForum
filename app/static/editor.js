/* global CodeMirror, marked, hljs, renderMathInElement */
(function () {
    function configureMarked() {
        if (typeof marked === 'undefined') {
            return;
        }
        marked.setOptions({
            gfm: true,
            breaks: true,
            highlight: function (code, lang) {
                if (typeof hljs === 'undefined') {
                    return code;
                }
                if (lang && hljs.getLanguage(lang)) {
                    return hljs.highlight(code, { language: lang }).value;
                }
                return hljs.highlightAuto(code).value;
            }
        });
    }

    function applyHighlight(target) {
        if (typeof hljs === 'undefined') {
            return;
        }
        target.querySelectorAll('pre code').forEach(function (block) {
            hljs.highlightElement(block);
        });
    }

    function applyMath(target) {
        if (typeof renderMathInElement !== 'function') {
            return;
        }
        renderMathInElement(target, {
            delimiters: [
                { left: '$$', right: '$$', display: true },
                { left: '$', right: '$', display: false },
                { left: '\\(', right: '\\)', display: false },
                { left: '\\[', right: '\\]', display: true }
            ],
            throwOnError: false
        });
    }

    function enhanceStaticMarkdown() {
        document.querySelectorAll('.markdown-body').forEach(function (section) {
            if (section.hasAttribute('data-md-enhanced')) {
                return;
            }
            section.setAttribute('data-md-enhanced', 'true');
            applyHighlight(section);
            applyMath(section);
        });
    }

    function surroundSelection(cm, token) {
        var doc = cm.getDoc();
        var selections = doc.listSelections();
        doc.operation(function () {
            selections.forEach(function (sel) {
                var from = sel.from();
                var to = sel.to();
                var selectedText = doc.getRange(from, to);
                if (!selectedText) {
                    var word = cm.findWordAt(from);
                    from = word.anchor;
                    to = word.head;
                    selectedText = doc.getRange(from, to);
                }
                doc.replaceRange(token + selectedText + token, from, to);
            });
        });
    }

    function prefixLines(cm, prefix) {
        var doc = cm.getDoc();
        var selections = doc.listSelections();
        doc.operation(function () {
            selections.forEach(function (sel) {
                var start = Math.min(sel.anchor.line, sel.head.line);
                var end = Math.max(sel.anchor.line, sel.head.line);
                for (var line = start; line <= end; line += 1) {
                    var content = doc.getLine(line) || '';
                    if (content.trim().length === 0) {
                        doc.replaceRange(prefix, { line: line, ch: 0 });
                    } else if (content.indexOf(prefix) !== 0) {
                        doc.replaceRange(prefix, { line: line, ch: 0 });
                    }
                }
            });
        });
    }

    function fenceBlock(cm, fence) {
        var doc = cm.getDoc();
        var selections = doc.listSelections();
        doc.operation(function () {
            selections.forEach(function (sel) {
                var from = sel.from();
                var to = sel.to();
                var selected = doc.getRange(from, to);
                if (!selected) {
                    selected = '';
                }
                var block = fence + '\n' + selected + (selected && !selected.endsWith('\n') ? '\n' : '') + fence + '\n';
                doc.replaceRange(block, from, to);
            });
        });
    }

    function bindToolbar(cm, toolbar) {
        if (!toolbar) {
            return;
        }
        toolbar.addEventListener('click', function (event) {
            var button = event.target.closest('.markdown-tool');
            if (!button) {
                return;
            }
            event.preventDefault();
            var dataset = button.dataset;
            if (dataset.mdSurround) {
                surroundSelection(cm, dataset.mdSurround);
            } else if (dataset.mdPrefix) {
                prefixLines(cm, dataset.mdPrefix);
            } else if (dataset.mdBlock) {
                fenceBlock(cm, dataset.mdBlock);
            }
            cm.focus();
        });
    }

    function initEditors() {
        if (typeof CodeMirror === 'undefined') {
            return;
        }
        document.querySelectorAll('.markdown-editor').forEach(function (container) {
            var textarea = container.querySelector('textarea[data-markdown-source]');
            var preview = container.querySelector('.markdown-preview');
            if (!textarea || container.hasAttribute('data-editor-loaded')) {
                return;
            }
            container.setAttribute('data-editor-loaded', 'true');
            var isCompact = container.classList.contains('compact');
            var cm = CodeMirror.fromTextArea(textarea, {
                mode: 'markdown',
                lineNumbers: !isCompact,
                lineWrapping: true,
                scrollbarStyle: 'simple',
                viewportMargin: isCompact ? 50 : Infinity,
                extraKeys: {
                    Enter: 'newlineAndIndentContinueMarkdownList'
                }
            });
            cm.setSize('100%', '100%');
            var renderPreview = function () {
                if (!preview) {
                    return;
                }
                var value = cm.getValue();
                if (typeof marked === 'undefined') {
                    preview.textContent = value;
                } else {
                    preview.innerHTML = marked.parse(value);
                }
                applyHighlight(preview);
                applyMath(preview);
            };
            renderPreview();
            cm.on('change', renderPreview);
            var form = container.closest('form');
            if (form) {
                form.addEventListener('submit', function () {
                    cm.save();
                });
            }
            bindToolbar(cm, container.querySelector('.markdown-toolbar'));
        });
    }

    function initTagTree() {
        document.querySelectorAll('.tag-toggle').forEach(function (button) {
            var targetId = button.getAttribute('data-toggle');
            if (!targetId) {
                return;
            }
            button.addEventListener('click', function () {
                var target = document.querySelector(targetId);
                if (!target) {
                    return;
                }
                var expanded = button.getAttribute('aria-expanded') === 'true';
                var nextState = !expanded;
                button.setAttribute('aria-expanded', nextState.toString());
                if (nextState) {
                    target.classList.remove('is-collapsed');
                } else {
                    target.classList.add('is-collapsed');
                }
            });
        });
    }

    function ready() {
        configureMarked();
        enhanceStaticMarkdown();
        initEditors();
        initTagTree();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', ready);
    } else {
        ready();
    }
})();
