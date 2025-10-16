(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        define([], factory);
    } else if (typeof module === 'object' && module.exports) {
        module.exports = factory();
    } else {
        root.MdKatexRenderer = factory();
    }
}(typeof self !== 'undefined' ? self : this, function () {
    'use strict';

    var markdownit = typeof window !== 'undefined' ? window.markdownit : undefined;
    var markdownitTaskLists = typeof window !== 'undefined' ? window.markdownitTaskLists : undefined;
    var markdownitContainer = typeof window !== 'undefined' ? window.markdownitContainer : undefined;

    var CALLOUT_KINDS = ['info', 'success', 'warning', 'error'];
    var CALLOUT_DEFAULT_TITLES = {
        info: 'Info',
        success: 'Success',
        warning: 'Warning',
        error: 'Error'
    };
    var CALLOUT_PATTERN = /^([\w-]+)(?:\[([^\]]*)\])?(?:\{([^}]*)\})?/;
    var MATH_SEGMENT_RE = /(\$\$[\s\S]*?\$\$|\\\[[\s\S]*?\\\]|\\\([\s\S]*?\\\)|\$(?!\$)[^$]*?\$)/g;
    var KATEX_BRACE_PLACEHOLDERS = {
        '\\{': 'KATEXLEFTBRACEPLACEHOLDER',
        '\\}': 'KATEXRIGHTBRACEPLACEHOLDER'
    };

    var mdInstance = null;

    function truthy(value) {
        if (value == null) {
            return false;
        }
        var normalized = String(value).trim().toLowerCase();
        return normalized !== '' &&
            normalized !== '0' &&
            normalized !== 'false' &&
            normalized !== 'none' &&
            normalized !== 'no' &&
            normalized !== 'off';
    }

    function protectKatexBraces(source) {
        if (!source) {
            return source;
        }
        return source.replace(MATH_SEGMENT_RE, function (segment) {
            Object.keys(KATEX_BRACE_PLACEHOLDERS).forEach(function (token) {
                var placeholder = KATEX_BRACE_PLACEHOLDERS[token];
                segment = segment.split(token).join(placeholder);
            });
            return segment;
        });
    }

    function restoreKatexBraces(html) {
        if (!html) {
            return html;
        }
        Object.keys(KATEX_BRACE_PLACEHOLDERS).forEach(function (token) {
            var placeholder = KATEX_BRACE_PLACEHOLDERS[token];
            html = html.split('\\' + placeholder).join(placeholder);
            html = html.split(placeholder).join(token);
        });
        return html;
    }

    function normalizeMathHtml(html) {
        if (!html || html.indexOf('<br') === -1) {
            return html;
        }
        return html.replace(/(\$\$[\s\S]*?\$\$|\\\[[\s\S]*?\\\])/g, function (segment) {
            return segment.replace(/<br\s*\/?>(?=\s*\n)/gi, '\n');
        });
    }

    function parseAttributes(raw) {
        if (!raw) {
            return {};
        }
        var attrs = {};
        raw.trim().split(/\s+/).forEach(function (part) {
            if (!part) {
                return;
            }
            if (part.indexOf('=') !== -1) {
                var pieces = part.split('=', 2);
                var key = pieces[0];
                var value = pieces[1].replace(/^['"]|['"]$/g, '');
                attrs[key] = value;
            } else {
                attrs[part] = 'true';
            }
        });
        return attrs;
    }

    function parseCalloutInfo(info) {
        if (!info) {
            return null;
        }
        var match = CALLOUT_PATTERN.exec(info.trim());
        if (!match) {
            return null;
        }
        var kind = match[1];
        if (CALLOUT_KINDS.indexOf(kind) === -1) {
            return null;
        }
        return {
            kind: kind,
            label: match[2] || CALLOUT_DEFAULT_TITLES[kind],
            attrs: parseAttributes(match[3])
        };
    }

    function ensureMarkdownIt() {
        if (mdInstance || !markdownit) {
            return mdInstance;
        }

        mdInstance = markdownit({
            html: false,
            linkify: true,
            breaks: true,
            highlight: function (str, lang) {
                if (typeof hljs === 'undefined') {
                    return '';
                }
                try {
                    if (lang && hljs.getLanguage(lang)) {
                        return hljs.highlight(str, { language: lang, ignoreIllegals: true }).value;
                    }
                    return hljs.highlightAuto(str).value;
                } catch (error) {
                    return '';
                }
            }
        })
            .enable('table')
            .enable('strikethrough');

        if (markdownitTaskLists) {
            mdInstance.use(markdownitTaskLists, { enabled: true });
        }

        if (markdownitContainer) {
            registerCalloutContainers(mdInstance);
        }

        return mdInstance;
    }

    function registerCalloutContainers(md) {
        var validate = function (params) {
            return parseCalloutInfo(params) !== null;
        };

        var render = function (tokens, idx, _options, _env) {
            var token = tokens[idx];
            var info = parseCalloutInfo(token.info || '') || {
                kind: 'info',
                label: CALLOUT_DEFAULT_TITLES.info,
                attrs: {}
            };
            var openAttr = truthy(info.attrs.open) ? ' open' : '';
            var classAttr = ' class="callout callout-' + info.kind + '"';
            if (token.nesting === 1) {
                var summaryHtml = renderInline(info.label);
                return (
                    '<details' + classAttr + openAttr + '>' +
                    '<summary><span class="callout-title">' + summaryHtml + '</span></summary>' +
                    '<div class="callout-content">'
                );
            }
            return '</div></details>';
        };

        CALLOUT_KINDS.forEach(function (kind) {
            md.use(markdownitContainer, kind, {
                validate: validate,
                render: render
            });
        });
    }

    function renderInline(content) {
        var md = ensureMarkdownIt();
        if (!md) {
            return content || '';
        }
        var protectedContent = protectKatexBraces(content || '');
        var rendered = md.renderInline(protectedContent);
        return restoreKatexBraces(rendered);
    }

    function renderMarkdown(source) {
        var md = ensureMarkdownIt();
        if (!md) {
            return source || '';
        }
        var protectedSource = protectKatexBraces(source || '');
        var html = md.render(protectedSource);
        return normalizeMathHtml(restoreKatexBraces(html));
    }

    function applyHighlight(target) {
        if (typeof hljs === 'undefined' || !target) {
            return;
        }
        target.querySelectorAll('pre code').forEach(function (block) {
            if (block.classList.contains('hljs')) {
                return;
            }
            if (block.firstElementChild && !block.classList.contains('hljs')) {
                block.classList.add('hljs');
            }
            if (block.firstElementChild) {
                return;
            }
            hljs.highlightElement(block);
        });
    }

    function applyMath(target) {
        if (typeof renderMathInElement !== 'function' || !target) {
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

    function applyPostProcessing(target) {
        applyHighlight(target);
        applyMath(target);
    }

    function enhanceStaticMarkdown() {
        ensureMarkdownIt();
        document.querySelectorAll('.markdown-body').forEach(function (section) {
            if (section.hasAttribute('data-md-enhanced')) {
                return;
            }
            section.setAttribute('data-md-enhanced', 'true');
            section.innerHTML = normalizeMathHtml(restoreKatexBraces(section.innerHTML));
            applyPostProcessing(section);
        });
    }

    function configure() {
        return ensureMarkdownIt() !== null;
    }

    var api = {
        configure: configure,
        render: renderMarkdown,
        renderInline: renderInline,
        applyPostProcessing: applyPostProcessing,
        enhanceStaticMarkdown: enhanceStaticMarkdown,
        protectKatexBraces: protectKatexBraces,
        restoreKatexBraces: restoreKatexBraces
    };

    if (typeof document !== 'undefined') {
        var onReady = function () {
            if (!configure()) {
                return;
            }
            enhanceStaticMarkdown();
        };
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', onReady);
        } else {
            onReady();
        }
    }

    return api;
}));
