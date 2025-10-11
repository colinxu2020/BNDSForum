/* global CodeMirror, MdKatexRenderer */
(function () {
    'use strict';

    function surroundSelection(cm, token) {
        var doc = cm.getDoc();
        var selections = doc.listSelections();
        cm.operation(function () {
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
        cm.operation(function () {
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
        cm.operation(function () {
            selections.forEach(function (sel) {
                var from = sel.from();
                var to = sel.to();
                var selected = doc.getRange(from, to) || '';
                var needsTrailingNewline = selected && !selected.endsWith('\n');
                var block = fence + '\n' + selected + (needsTrailingNewline ? '\n' : '') + fence + '\n';
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
        if (typeof MdKatexRenderer === 'undefined') {
            return;
        }
        MdKatexRenderer.configure();

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
                if (typeof MdKatexRenderer.render !== 'function') {
                    preview.textContent = value;
                    return;
                }
                var html = MdKatexRenderer.render(value);
                preview.innerHTML = html;
                MdKatexRenderer.applyPostProcessing(preview);
            };

            renderPreview();

            var requiredMessage = textarea.getAttribute('data-required-message') || '';
            var handleChange = function () {
                renderPreview();
                if (!requiredMessage) {
                    return;
                }
                if (container.classList.contains('has-error') && cm.getValue().trim().length > 0) {
                    container.classList.remove('has-error');
                    var hintNode = container.querySelector('.markdown-error');
                    if (hintNode) {
                        hintNode.remove();
                    }
                }
            };

            cm.on('change', handleChange);

            var form = container.closest('form');
            if (form) {
                form.addEventListener('submit', function (event) {
                    var value = cm.getValue().trim();
                    if (requiredMessage && value.length === 0) {
                        event.preventDefault();
                        container.classList.add('has-error');
                        var hint = container.querySelector('.markdown-error');
                        if (!hint) {
                            hint = document.createElement('p');
                            hint.className = 'markdown-error';
                            container.appendChild(hint);
                        }
                        hint.textContent = requiredMessage;
                        cm.focus();
                        return;
                    }
                    container.classList.remove('has-error');
                    var existing = container.querySelector('.markdown-error');
                    if (existing) {
                        existing.remove();
                    }
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
        if (typeof MdKatexRenderer !== 'undefined') {
            MdKatexRenderer.configure();
            MdKatexRenderer.enhanceStaticMarkdown();
        }
        initEditors();
        initTagTree();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', ready);
    } else {
        ready();
    }
})();
