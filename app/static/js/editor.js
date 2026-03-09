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

    function bindToolbar(cm, toolbar, preview) {
        if (!toolbar) {
            return;
        }

        var syncScrollEnabled = false;
        var syncScrollHandler = null;

        function enableSyncScroll() {
            if (!preview) return;
            syncScrollHandler = function () {
                var info = cm.getScrollInfo();
                var ratio = info.top / Math.max(1, info.height - info.clientHeight);
                preview.scrollTop = ratio * Math.max(0, preview.scrollHeight - preview.clientHeight);
            };
            cm.on('scroll', syncScrollHandler);
        }

        function disableSyncScroll() {
            if (syncScrollHandler) {
                cm.off('scroll', syncScrollHandler);
                syncScrollHandler = null;
            }
        }

        toolbar.addEventListener('click', function (event) {
            var button = event.target.closest('.markdown-tool');
            if (!button) {
                return;
            }
            event.preventDefault();

            // 同步滚动切换
            if (button.dataset.mdAction === 'sync-scroll') {
                syncScrollEnabled = !syncScrollEnabled;
                button.setAttribute('aria-pressed', syncScrollEnabled.toString());
                button.title = syncScrollEnabled ? '关闭同步滚动' : '同步滚动（编辑器⇔预览）';
                button.style.color = syncScrollEnabled ? 'var(--primary)' : '';
                if (syncScrollEnabled) {
                    enableSyncScroll();
                } else {
                    disableSyncScroll();
                }
                cm.focus();
                return;
            }

            // 全屏切换
            if (button.dataset.mdAction === 'fullscreen') {
                var container = button.closest('.markdown-editor');
                if (container) {
                    var isFullscreen = container.classList.toggle('is-fullscreen');
                    button.title = isFullscreen ? '退出全屏' : '全屏';
                    button.setAttribute('aria-pressed', isFullscreen.toString());
                    // 防止 body 滚动
                    document.body.style.overflow = isFullscreen ? 'hidden' : '';
                    // 刷新 CodeMirror 布局
                    setTimeout(function () { cm.refresh(); }, 50);
                }
                cm.focus();
                return;
            }

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

    // ── 编辑器内联通知（用于粘贴上传反馈） ──
    function _showEditorNotice(container, message, type) {
        var existing = container.querySelector('.editor-paste-notice');
        if (existing) { existing.remove(); }
        var el = document.createElement('div');
        el.className = 'editor-paste-notice editor-paste-notice--' + (type || 'info');
        el.textContent = message;
        el.style.cssText = 'position:absolute;bottom:6px;right:10px;z-index:999;padding:.3rem .75rem;border-radius:6px;font-size:.82rem;pointer-events:none;opacity:1;transition:opacity .4s;';
        if (type === 'error') { el.style.background = '#fee2e2'; el.style.color = '#b91c1c'; }
        else if (type === 'success') { el.style.background = '#d1fae5'; el.style.color = '#065f46'; }
        else { el.style.background = '#dbeafe'; el.style.color = '#1d4ed8'; }
        container.style.position = container.style.position || 'relative';
        container.appendChild(el);
        setTimeout(function () { el.style.opacity = '0'; setTimeout(function () { el.remove(); }, 450); }, 2800);
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

            bindToolbar(cm, container.querySelector('.markdown-toolbar'), preview);

            // 暴露 CM 实例供外部脚本访问（如离开确认检测）
            container._cm = cm;

            // ── 粘贴图片自动上传到图床 ──
            cm.on('paste', function (cmInstance, event) {
                var clipData = event.clipboardData || (event.originalEvent && event.originalEvent.clipboardData);
                if (!clipData || !clipData.items) { return; }
                var ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/gif', 'image/webp', 'image/bmp'];
                for (var i = 0; i < clipData.items.length; i++) {
                    var item = clipData.items[i];
                    if (item.kind !== 'file') { continue; }
                    if (ALLOWED_TYPES.indexOf(item.type) === -1) {
                        // 只提示一次，其他类型让默认行为处理
                        continue;
                    }
                    event.preventDefault();
                    var imgFile = item.getAsFile();
                    if (!imgFile || imgFile.size === 0) {
                        _showEditorNotice(container, '粘贴的图片为空', 'error');
                        return;
                    }
                    var MAX_PASTE_SIZE = 20 * 1024 * 1024;
                    if (imgFile.size > MAX_PASTE_SIZE) {
                        _showEditorNotice(container, '图片过大（最大 20 MB）', 'error');
                        return;
                    }
                    var ext = item.type.split('/')[1] || 'png';
                    var fd = new FormData();
                    fd.append('file', imgFile, 'paste-' + Date.now() + '.' + ext);
                    var csrfToken = (document.querySelector('meta[name="csrf-token"]') || {}).content || '';
                    var uploadUrl = container.getAttribute('data-upload-url') || '/uploads/api/upload';
                    var placeholder = '![上传中...]()';
                    var cursor = cmInstance.getCursor();
                    cmInstance.replaceSelection(placeholder);
                    _showEditorNotice(container, '正在上传图片…', 'info');
                    var xhr = new XMLHttpRequest();
                    xhr.open('POST', uploadUrl, true);
                    xhr.setRequestHeader('X-CSRFToken', csrfToken);
                    xhr.onload = (function (cur, ph) {
                        return function () {
                            try {
                                var res = JSON.parse(xhr.responseText);
                                if (res.success && res.data && res.data.url) {
                                    var imgMd = '![图片](' + res.data.url + ')';
                                    var content = cmInstance.getValue();
                                    var replaced = content.replace(ph, imgMd);
                                    if (replaced !== content) {
                                        cmInstance.setValue(replaced);
                                    } else {
                                        cmInstance.replaceSelection(imgMd);
                                    }
                                    _showEditorNotice(container, '图片上传成功 ✓', 'success');
                                } else {
                                    // 回退：移除占位符
                                    var c2 = cmInstance.getValue().replace(ph, '');
                                    cmInstance.setValue(c2);
                                    _showEditorNotice(container, '上传失败：' + (res.message || '未知错误'), 'error');
                                }
                            } catch (e) {
                                _showEditorNotice(container, '上传响应解析失败', 'error');
                            }
                        };
                    }(cursor, placeholder));
                    xhr.onerror = function () {
                        var c2 = cmInstance.getValue().replace(placeholder, '');
                        cmInstance.setValue(c2);
                        _showEditorNotice(container, '网络错误，上传失败', 'error');
                    };
                    xhr.send(fd);
                    break; // 每次粘贴只处理第一张图片
                }
            });

            document.dispatchEvent(new CustomEvent('mdeditor:ready', { detail: { cm: cm, container: container } }));
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

    function exitAllFullscreen() {
        document.querySelectorAll('.markdown-editor.is-fullscreen').forEach(function (editor) {
            editor.classList.remove('is-fullscreen');
            var btn = editor.querySelector('[data-md-action="fullscreen"]');
            if (btn) {
                btn.title = '全屏';
                btn.setAttribute('aria-pressed', 'false');
            }
        });
        document.body.style.overflow = '';
        // Refresh all CodeMirror instances
        document.querySelectorAll('.CodeMirror').forEach(function (el) {
            if (el.CodeMirror) {
                el.CodeMirror.refresh();
            }
        });
    }

    function ready() {
        if (typeof MdKatexRenderer !== 'undefined') {
            MdKatexRenderer.configure();
            MdKatexRenderer.enhanceStaticMarkdown();
        }
        initEditors();
        initTagTree();
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                exitAllFullscreen();
            }
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', ready);
    } else {
        ready();
    }
})();
