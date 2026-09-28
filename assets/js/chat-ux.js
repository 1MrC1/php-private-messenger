(function () {
    'use strict';

    if (window.pmSecurityHardeningReady !== true) {
        console.error('Chat UX enhancements require the security hardening layer.');
        return;
    }

    const MAX_RECORDING_BYTES = 50 * 1024 * 1024;
    const MAX_RECORDING_MS = 5 * 60 * 1000;
    const WIDE_PANEL_QUERY = '(min-width: 1200px)';
    const EMOJI = Object.freeze([
        '😀', '😃', '😄', '😁', '😆', '😅', '😂', '🥹',
        '😊', '😍', '🥰', '😘', '🤩', '🥳', '😎', '🤔',
        '😮', '😢', '😭', '😤', '😡', '🤯', '😱', '🤗',
        '👍', '👎', '👏', '🙌', '👌', '✌️', '🤝', '💪',
        '❤️', '🧡', '💛', '💚', '💙', '💜', '💯', '✨',
        '🎉', '🔥', '🌟', '💡', '👀', '🙏', '💬', '✅'
    ]);

    const uxState = {
        delivery: new Map(),
        pinned: new Set(),
        muted: new Set(),
        preferencesUserId: null,
        rowMenuChatId: null,
        searchAbort: null,
        searchTimer: null,
        searchSequence: 0,
        searchResults: [],
        searchIndex: -1,
        searchChatId: null,
        completedSearchCount: null,
        sidePanelOpener: null,
        readQueues: new Map(),
        timelineDecorating: false,
        reviewingSearchContext: false,
        searchContextReviewStartedAt: 0,
        searchContextHasMoreAfter: false,
        voice: {
            mode: 'idle',
            requestToken: 0,
            session: null,
            file: null,
            sourceChatId: null,
            objectUrl: null
        }
    };

    function positiveInteger(value) {
        const number = Number(value);
        return Number.isSafeInteger(number) && number > 0 ? number : null;
    }

    function activeChatId() {
        return positiveInteger(typeof currentChatId === 'undefined' ? null : currentChatId);
    }

    function activeUserId() {
        return positiveInteger(typeof currentUser === 'undefined' || !currentUser ? null : currentUser.id);
    }

    function toast(message, type) {
        if (typeof window.showToast === 'function') {
            window.showToast(message, type || 'info');
        }
    }

    function localized(key, parameters, fallback) {
        if (window.PmI18n && typeof window.PmI18n.t === 'function') {
            const value = window.PmI18n.t(key, parameters || {});
            if (value !== key) return value;
        }
        return fallback === undefined ? key : fallback;
    }

    function localizedCount(key, count, fallback) {
        if (window.PmI18n && typeof window.PmI18n.tc === 'function') {
            const value = window.PmI18n.tc(key, count, {count: count});
            if (value !== key) return value;
        }
        return fallback;
    }

    function localizedLiteral(value) {
        return window.PmI18n && typeof window.PmI18n.translate === 'function'
            ? window.PmI18n.translate(value)
            : value;
    }

    function localizedNumber(value) {
        return window.PmI18n && typeof window.PmI18n.formatNumber === 'function'
            ? window.PmI18n.formatNumber(value)
            : String(value);
    }

    function normalizedMime(value) {
        return String(value || '').toLowerCase().split(';', 1)[0].trim();
    }

    function isVisibleFocusTarget(element) {
        return Boolean(element && element.isConnected && !element.closest('[inert]') &&
            !element.closest('[aria-hidden="true"]') && element.getClientRects().length > 0 &&
            !element.hidden && !element.disabled);
    }

    function parseTimestamp(value) {
        if (typeof window.parsePmTimestamp === 'function') {
            return window.parsePmTimestamp(value);
        }
        const text = String(value || '').trim();
        if (!text) return null;
        const mysql = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})$/.exec(text);
        const date = new Date(mysql ? mysql[1] + 'T' + mysql[2] + 'Z' : text);
        return Number.isNaN(date.getTime()) ? null : date;
    }

    function preferenceStorageKey(userId) {
        return 'pm.chat-preferences.v1.' + String(userId);
    }

    function sanitizeIdSet(value) {
        const result = new Set();
        (Array.isArray(value) ? value : []).slice(0, 500).forEach(function (candidate) {
            const id = positiveInteger(candidate);
            if (id) result.add(id);
        });
        return result;
    }

    function loadPreferences() {
        const userId = activeUserId();
        if (!userId || uxState.preferencesUserId === userId) return;
        uxState.preferencesUserId = userId;
        uxState.pinned = new Set();
        uxState.muted = new Set();
        try {
            const raw = window.localStorage.getItem(preferenceStorageKey(userId));
            const parsed = raw ? JSON.parse(raw) : {};
            uxState.pinned = sanitizeIdSet(parsed && parsed.pinned);
            uxState.muted = sanitizeIdSet(parsed && parsed.muted);
        } catch (error) {
            console.debug('Chat preferences could not be loaded:', error);
        }
    }

    function savePreferences() {
        const userId = activeUserId();
        if (!userId) return;
        try {
            window.localStorage.setItem(preferenceStorageKey(userId), JSON.stringify({
                pinned: Array.from(uxState.pinned),
                muted: Array.from(uxState.muted)
            }));
        } catch (error) {
            console.debug('Chat preferences could not be saved:', error);
        }
    }

    function truncateDraft(value) {
        const text = String(value || '').replace(/\s+/g, ' ').trim();
        return text.length > 52 ? text.slice(0, 51) + '…' : text;
    }

    function setTextIfChanged(element, value) {
        if (element && element.textContent !== value) element.textContent = value;
    }

    /**
     * Keep the protected-conversation caveat in step with the open chat. Driven
     * from the row the server marked, so a client cannot show a stronger claim
     * than the server supports.
     */
    function refreshProtectedBanner() {
        const banner = document.getElementById('protectedBanner');
        if (!banner) return;
        const chatId = activeChatId();
        const row = chatId
            ? document.querySelector('.chat-item[data-chat-id="' + chatId + '"]')
            : null;
        const isProtected = !!row && row.dataset.protected === 'true';
        banner.classList.toggle('d-none', !isProtected);
    }

    function decorateConversationRows() {
        loadPreferences();
        const list = document.getElementById('chatList');
        if (!list) return;
        list.setAttribute('role', 'listbox');
        list.setAttribute('aria-label', 'Conversations');

        const rows = Array.from(list.querySelectorAll('.chat-item[data-chat-id]'));
        rows.forEach(function (row) {
            const chatId = positiveInteger(row.dataset.chatId);
            if (!chatId) return;
            const obsoleteButton = row.querySelector('.chat-row-menu-button');
            if (obsoleteButton) obsoleteButton.remove();
            row.setAttribute('aria-haspopup', 'menu');
            row.setAttribute('aria-keyshortcuts', 'Shift+F10');
            const preview = row.querySelector('.chat-last-message');
            const delivery = row.querySelector('.chat-delivery-status');
            const hasDraft = row.dataset.hasDraft === 'true';
            const activeDraft = chatId === activeChatId() && hasDraft
                ? truncateDraft((document.getElementById('messageInput') || {}).value)
                : '';
            const deliveryEntry = uxState.delivery.get(chatId);
            const currentSendState = deliveryEntry && deliveryEntry.active
                ? {state: 'sending'}
                : (deliveryEntry && deliveryEntry.unconfirmed.size ? {state: 'unconfirmed'} : null);
            row.classList.toggle('is-pinned', uxState.pinned.has(chatId));
            row.classList.toggle('is-muted', uxState.muted.has(chatId));
            row.classList.toggle('is-sending', Boolean(currentSendState && currentSendState.state === 'sending'));
            row.classList.toggle('is-unconfirmed', Boolean(currentSendState && currentSendState.state === 'unconfirmed'));
            row.classList.toggle('has-draft', hasDraft);

            if (preview) {
                if (currentSendState && currentSendState.state === 'sending') {
                    setTextIfChanged(preview, localized('chat.state.sending', {}, 'Sending…'));
                } else if (currentSendState && currentSendState.state === 'unconfirmed') {
                    setTextIfChanged(preview, localized('chat.state.unconfirmed', {}, 'Delivery unconfirmed'));
                } else if (hasDraft) {
                    setTextIfChanged(preview, activeDraft
                        ? localized('chat.draft_preview', {text: activeDraft}, 'Draft: ' + activeDraft)
                        : localized('chat.draft', {}, 'Draft'));
                } else {
                    setTextIfChanged(
                        preview,
                        row.dataset.serverPreview || localized('chat.no_messages', {}, 'No messages yet')
                    );
                }
            }
            if (delivery) {
                delivery.hidden = Boolean(currentSendState || hasDraft) || !delivery.textContent;
            }

            const name = row.querySelector('.chat-name');
            const title = name ? name.textContent : 'conversation';
            const labels = [localized('chat.open_named', {name: title}, 'Open chat: ' + title)];
            if (uxState.pinned.has(chatId)) labels.push(localized('chat.row.pinned', {}, 'pinned on this device'));
            if (uxState.muted.has(chatId)) labels.push(localized('chat.row.muted', {}, 'reduced prominence on this device'));
            if (hasDraft) labels.push(localized('chat.row.has_draft', {}, 'has a draft'));
            if (currentSendState && currentSendState.state === 'unconfirmed') {
                labels.push(localized('chat.row.delivery_unconfirmed', {}, 'delivery unconfirmed'));
            }
            row.setAttribute('aria-label', labels.join(', '));
        });

        const preferredOrder = rows.filter(function (row) {
            return uxState.pinned.has(positiveInteger(row.dataset.chatId));
        }).concat(rows.filter(function (row) {
            return !uxState.pinned.has(positiveInteger(row.dataset.chatId));
        }));
        const orderChanged = preferredOrder.some(function (row, index) {
            return list.children[index] !== row;
        });
        if (orderChanged) {
            preferredOrder.forEach(function (row) { list.appendChild(row); });
        }

        if (typeof window.syncConversationRovingTabStop === 'function') {
            window.syncConversationRovingTabStop();
        }
        updateSelectedChatPreferenceLabels();
    }

    window.refreshConversationRowStates = decorateConversationRows;

    function openChatRowMenu(chatId, trigger, anchor) {
        const safeChatId = positiveInteger(chatId);
        const menu = document.getElementById('chatRowMenu');
        if (!safeChatId || !menu) return;
        uxState.rowMenuChatId = safeChatId;
        const pinLabel = menu.querySelector('[data-chat-pref-label="pin"]');
        const muteLabel = menu.querySelector('[data-chat-pref-label="mute"]');
        const pinAction = menu.querySelector('[data-pm-action="chat-pref-pin"]');
        const muteAction = menu.querySelector('[data-pm-action="chat-pref-mute"]');
        if (pinLabel) pinLabel.textContent = uxState.pinned.has(safeChatId) ? 'Unpin on this device' : 'Pin on this device';
        if (muteLabel) muteLabel.textContent = uxState.muted.has(safeChatId) ? 'Restore prominence on this device' : 'Reduce prominence on this device';
        if (pinAction) pinAction.setAttribute('aria-checked', uxState.pinned.has(safeChatId) ? 'true' : 'false');
        if (muteAction) muteAction.setAttribute('aria-checked', uxState.muted.has(safeChatId) ? 'true' : 'false');
        menu.hidden = false;
        menu.classList.add('show');
        menu.__pmTrigger = trigger || null;
        menu.style.removeProperty('top');
        menu.style.removeProperty('right');
        menu.style.removeProperty('bottom');
        menu.style.removeProperty('left');
        if (!window.matchMedia || !window.matchMedia('(max-width: 768px)').matches) {
            const triggerRect = trigger && typeof trigger.getBoundingClientRect === 'function'
                ? trigger.getBoundingClientRect()
                : null;
            const menuRect = menu.getBoundingClientRect();
            const margin = 8;
            const requestedX = anchor && Number.isFinite(anchor.x)
                ? anchor.x
                : (triggerRect ? triggerRect.right - menuRect.width : margin);
            const requestedY = anchor && Number.isFinite(anchor.y)
                ? anchor.y
                : (triggerRect ? triggerRect.bottom : margin);
            const maxLeft = Math.max(margin, window.innerWidth - menuRect.width - margin);
            const maxTop = Math.max(margin, window.innerHeight - menuRect.height - margin);
            const left = Math.min(Math.max(margin, requestedX), maxLeft);
            let top = requestedY;
            if (top > maxTop && triggerRect) top = triggerRect.top - menuRect.height;
            top = Math.min(Math.max(margin, top), maxTop);
            menu.style.left = Math.round(left) + 'px';
            menu.style.top = Math.round(top) + 'px';
            menu.style.right = 'auto';
            menu.style.bottom = 'auto';
        }
        const first = menu.querySelector('[role="menuitem"], button');
        if (first) first.focus({preventScroll: true});
    }

    function closeChatRowMenu(restoreFocus) {
        const menu = document.getElementById('chatRowMenu');
        if (!menu || menu.hidden) return;
        const trigger = menu.__pmTrigger;
        menu.hidden = true;
        menu.classList.remove('show');
        menu.style.removeProperty('top');
        menu.style.removeProperty('right');
        menu.style.removeProperty('bottom');
        menu.style.removeProperty('left');
        menu.__pmTrigger = null;
        uxState.rowMenuChatId = null;
        if (trigger && trigger.dataset) delete trigger.dataset.suppressNextClick;
        if (restoreFocus && trigger && trigger.isConnected) trigger.focus({preventScroll: true});
    }

    window.closeChatRowPreferenceMenu = closeChatRowMenu;

    function updateSelectedChatPreferenceLabels() {
        const chatId = activeChatId();
        const pinLabel = document.querySelector('[data-active-chat-pref-label="pin"]');
        const muteLabel = document.querySelector('[data-active-chat-pref-label="mute"]');
        setTextIfChanged(pinLabel, chatId && uxState.pinned.has(chatId)
            ? localizedLiteral('Unpin on this device')
            : localizedLiteral('Pin on this device'));
        setTextIfChanged(muteLabel, chatId && uxState.muted.has(chatId)
            ? localizedLiteral('Restore prominence on this device')
            : localizedLiteral('Reduce prominence on this device'));
    }

    function toggleChatPreference(kind, explicitChatId) {
        const chatId = positiveInteger(explicitChatId) || uxState.rowMenuChatId;
        if (!chatId) return;
        const target = kind === 'pin' ? uxState.pinned : uxState.muted;
        const enabled = !target.has(chatId);
        if (enabled) target.add(chatId);
        else target.delete(chatId);
        savePreferences();
        if (uxState.rowMenuChatId) closeChatRowMenu(true);
        decorateConversationRows();
        refreshProtectedBanner();
        toast((kind === 'pin' ? (enabled ? 'Conversation pinned' : 'Conversation unpinned') :
            (enabled ? 'Conversation de-emphasized' : 'Conversation prominence restored')) + ' on this device', 'success');
    }

    function widePanelAvailable() {
        return Boolean(window.matchMedia && window.matchMedia(WIDE_PANEL_QUERY).matches && activeChatId());
    }

    function setSidePanelView(view) {
        const search = document.getElementById('chatSidePanelSearchView');
        const info = document.getElementById('chatSidePanelInfoView');
        if (search) {
            search.hidden = view !== 'search';
            search.classList.toggle('d-none', view !== 'search');
        }
        if (info) {
            info.hidden = view !== 'info';
            info.classList.toggle('d-none', view !== 'info');
        }
        document.querySelectorAll('[data-chat-panel-view]').forEach(function (button) {
            const active = button.dataset.chatPanelView === view;
            button.classList.toggle('active', active);
            button.setAttribute('aria-pressed', active ? 'true' : 'false');
            button.setAttribute('aria-selected', active ? 'true' : 'false');
            button.tabIndex = active ? 0 : -1;
        });
        const title = document.getElementById('chatSidePanelTitle');
        if (title) title.textContent = view === 'info' ? 'Chat information' : 'Search messages';
        document.querySelectorAll('[aria-controls="chatSidePanel"]').forEach(function (button) {
            const active = (view === 'info' && button.dataset.pmAction === 'chat-info') ||
                (view === 'search' && button.dataset.pmAction === 'chat-search');
            button.setAttribute('aria-expanded', active ? 'true' : 'false');
        });
    }

    window.openChatSidePanel = function openChatSidePanel(view) {
        const panel = document.getElementById('chatSidePanel');
        const content = document.getElementById('chatContent');
        if (!panel || !content || !widePanelAvailable()) return false;
        if (panel.hidden && document.activeElement instanceof Element) {
            uxState.sidePanelOpener = document.activeElement;
        }
        panel.hidden = false;
        panel.setAttribute('aria-hidden', 'false');
        content.classList.add('side-panel-open');
        setSidePanelView(view === 'info' ? 'info' : 'search');
        return true;
    };

    window.closeChatSidePanel = function closeChatSidePanel(restoreFocus) {
        const panel = document.getElementById('chatSidePanel');
        const content = document.getElementById('chatContent');
        if (!panel || !content) return;
        panel.hidden = true;
        panel.setAttribute('aria-hidden', 'true');
        content.classList.remove('side-panel-open');
        document.querySelectorAll('[aria-controls="chatSidePanel"]').forEach(function (button) {
            button.setAttribute('aria-expanded', 'false');
        });
        cancelChatSearch();
        if (restoreFocus) {
            const button = [
                uxState.sidePanelOpener,
                document.querySelector('.chat-search-button'),
                document.querySelector('.chat-info-button'),
                document.getElementById('messageInput')
            ].find(isVisibleFocusTarget);
            if (button) button.focus({preventScroll: true});
        }
        uxState.sidePanelOpener = null;
    };

    function searchInputFor(source) {
        if (source instanceof HTMLInputElement &&
            (source.id === 'chatSearchInput' || source.id === 'chatSideSearchInput')) return source;
        if (document.activeElement instanceof HTMLInputElement &&
            (document.activeElement.id === 'chatSearchInput' || document.activeElement.id === 'chatSideSearchInput')) {
            return document.activeElement;
        }
        if (document.getElementById('chatContent') && document.getElementById('chatContent').classList.contains('side-panel-open')) {
            return document.getElementById('chatSideSearchInput');
        }
        return document.getElementById('chatSearchInput');
    }

    function searchResultTarget(input) {
        return input && input.id === 'chatSideSearchInput' ? 'chatSideSearchResults' : 'chatSearchResults';
    }

    function setSearchStatus(message, count) {
        const status = document.getElementById('chatSideSearchStatus');
        if (status) status.textContent = message;
        const modalStatus = document.getElementById('chatSearchStatus');
        if (modalStatus) {
            modalStatus.textContent = message || (Number.isSafeInteger(count) && count > 0
                ? localizedCount('chat.search.results', count, count === 1 ? '1 result' : count + ' results')
                : localized('chat.search.minimum', {}, 'Enter at least two characters.'));
        }
        if (Number.isSafeInteger(count)) refreshSearchCountOutput(count);
        if (Number.isSafeInteger(count)) {
            document.querySelectorAll('[data-pm-action="chat-side-search-prev"], [data-pm-action="chat-side-search-next"]').forEach(function (button) {
                button.disabled = count < 1;
            });
        }
    }

    function refreshSearchCountOutput(count) {
        const output = document.getElementById('chatSideSearchCount');
        if (!output || !Number.isSafeInteger(count)) return;
        output.textContent = localizedCount(
            'chat.search.results',
            count,
            count === 1 ? '1 result' : count + ' results'
        );
    }

    function renderSearchPrompt(targetId, message, explanation) {
        const target = document.getElementById(targetId);
        if (!target) return;
        target.replaceChildren();
        const empty = document.createElement('div');
        empty.className = 'modal-empty-state';
        const icon = document.createElement('span');
        const glyph = document.createElement('i');
        glyph.className = 'fas fa-search';
        glyph.setAttribute('aria-hidden', 'true');
        icon.appendChild(glyph);
        const strong = document.createElement('strong');
        strong.textContent = message;
        const hint = document.createElement('p');
        hint.textContent = explanation || 'Enter at least two characters to search this conversation.';
        empty.append(icon, strong, hint);
        target.appendChild(empty);
    }

    function cancelChatSearch() {
        uxState.searchSequence += 1;
        if (uxState.searchTimer) window.clearTimeout(uxState.searchTimer);
        uxState.searchTimer = null;
        if (uxState.searchAbort) uxState.searchAbort.abort();
        uxState.searchAbort = null;
        uxState.searchResults = [];
        uxState.searchIndex = -1;
        uxState.searchChatId = null;
        uxState.completedSearchCount = null;
        setSearchStatus('', 0);
        ['chatSearchInput', 'chatSideSearchInput'].forEach(function (inputId) {
            const input = document.getElementById(inputId);
            if (input) input.value = '';
        });
        const clearButton = document.querySelector('[data-pm-action="chat-side-search-clear"]');
        if (clearButton) clearButton.hidden = true;
        ['chatSearchResults', 'chatSideSearchResults'].forEach(function (targetId) {
            const target = document.getElementById(targetId);
            if (target) {
                target.setAttribute('aria-busy', 'false');
                renderSearchPrompt(targetId, 'Find a message');
            }
        });
    }

    const legacyShowChatSearch = window.showChatSearch;
    window.showChatSearch = function showResponsiveChatSearch() {
        if (window.openChatSidePanel('search')) {
            const input = document.getElementById('chatSideSearchInput');
            if (input) window.setTimeout(function () { input.focus(); }, 0);
            return;
        }
        if (typeof legacyShowChatSearch === 'function') legacyShowChatSearch.apply(this, arguments);
    };

    function performChatSearch(source) {
        const input = searchInputFor(source);
        const query = input ? input.value.trim() : '';
        const targetId = searchResultTarget(input);
        const target = document.getElementById(targetId);
        const clearButton = input && input.id === 'chatSideSearchInput'
            ? document.querySelector('[data-pm-action="chat-side-search-clear"]')
            : null;
        if (clearButton) clearButton.hidden = query.length === 0;
        const chatId = activeChatId();
        const sequence = ++uxState.searchSequence;
        if (uxState.searchAbort) uxState.searchAbort.abort();
        uxState.searchAbort = null;

        if (!chatId || query.length < 2) {
            if (target) target.setAttribute('aria-busy', 'false');
            uxState.searchResults = [];
            uxState.searchIndex = -1;
            uxState.completedSearchCount = null;
            renderSearchPrompt(targetId, chatId ? 'Find a message' : 'Select a conversation first');
            setSearchStatus('', 0);
            return;
        }

        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        uxState.searchAbort = controller;
        uxState.searchChatId = chatId;
        uxState.completedSearchCount = null;
        if (target) target.setAttribute('aria-busy', 'true');
        renderSearchPrompt(targetId, 'Searching…', 'Please wait while this conversation is searched.');
        setSearchStatus('Searching…', 0);
        window.fetch('api/chat.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            signal: controller ? controller.signal : undefined,
            body: JSON.stringify({action: 'search_messages', chat_id: chatId, query: query})
        }).then(function (response) {
            if (!response.ok) throw new Error('Search request failed');
            return response.json();
        }).then(function (data) {
            if (sequence !== uxState.searchSequence || chatId !== activeChatId() ||
                uxState.searchChatId !== chatId) return;
            if (!data || data.success !== true || !Array.isArray(data.messages)) {
                throw new Error('Search response was invalid');
            }
            uxState.searchResults = data.messages.map(function (message) {
                return positiveInteger(message && message.id);
            }).filter(Boolean);
            uxState.searchIndex = uxState.searchResults.length ? 0 : -1;
            uxState.completedSearchCount = uxState.searchResults.length;
            window.renderSearchResults(data.messages, query, targetId);
            setSearchStatus('Search complete', uxState.searchResults.length);
        }).catch(function (error) {
            if (error && error.name === 'AbortError') return;
            if (sequence !== uxState.searchSequence || chatId !== activeChatId()) return;
            console.error('Search messages error:', error);
            uxState.completedSearchCount = null;
            renderSearchPrompt(targetId, 'Search is unavailable');
            setSearchStatus('Search failed', 0);
        }).finally(function () {
            if (sequence === uxState.searchSequence && uxState.searchAbort === controller) {
                if (target) target.setAttribute('aria-busy', 'false');
                uxState.searchAbort = null;
            }
        });
    }

    window.searchInChat = function searchInActiveChat(source) {
        const input = searchInputFor(source);
        if (uxState.searchTimer) window.clearTimeout(uxState.searchTimer);
        uxState.searchTimer = null;
        if (!input || input.value.trim().length < 2) {
            performChatSearch(input);
            return;
        }
        uxState.searchTimer = window.setTimeout(function () {
            uxState.searchTimer = null;
            performChatSearch(input);
        }, 250);
    };

    function closeSearchModal() {
        const modal = document.getElementById('chatSearchModal');
        if (!modal || !window.bootstrap || !bootstrap.Modal) return;
        const instance = bootstrap.Modal.getInstance(modal);
        if (instance) instance.hide();
    }

    function highlightMessage(message) {
        if (!message) return;
        message.scrollIntoView({behavior: 'smooth', block: 'center'});
        message.classList.remove('message-jump-highlight');
        window.requestAnimationFrame(function () {
            message.classList.add('message-jump-highlight');
            window.setTimeout(function () { message.classList.remove('message-jump-highlight'); }, 2200);
        });
    }

    window.openMessageSearchResult = function openMessageSearchResult(messageId) {
        const safeMessageId = positiveInteger(messageId);
        const chatId = activeChatId();
        if (!safeMessageId || !chatId) return;
        const sequence = ++uxState.searchSequence;
        if (uxState.searchAbort) uxState.searchAbort.abort();
        uxState.searchAbort = null;
        const selectedIndex = uxState.searchResults.indexOf(safeMessageId);
        if (selectedIndex >= 0) uxState.searchIndex = selectedIndex;
        const existing = document.querySelector('#messagesList [data-message-id="' + safeMessageId + '"]');
        if (existing) {
            document.querySelectorAll('#chatSearchResults, #chatSideSearchResults').forEach(function (target) {
                target.setAttribute('aria-busy', 'false');
            });
            closeSearchModal();
            highlightMessage(existing);
            return;
        }

        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        uxState.searchAbort = controller;
        setSearchStatus('Loading message…');
        window.fetch('api/chat.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            signal: controller ? controller.signal : undefined,
            body: JSON.stringify({
                action: 'get_message_context',
                chat_id: chatId,
                message_id: safeMessageId,
                before_limit: 20,
                after_limit: 20
            })
        }).then(function (response) {
            if (!response.ok) throw new Error('Message context request failed');
            return response.json();
        }).then(function (data) {
            if (sequence !== uxState.searchSequence || chatId !== activeChatId()) return;
            if (!data || data.success !== true || !Array.isArray(data.messages)) {
                throw new Error('Message context response was invalid');
            }
            if (typeof window.cancelActiveMessageLoad === 'function') {
                window.cancelActiveMessageLoad();
            }
            if (typeof window.cancelNewMessagePoll === 'function') {
                window.cancelNewMessagePoll();
            }
            uxState.searchContextHasMoreAfter = data.has_more_after === true;
            setSearchContextReviewing(true);
            window.renderMessages(data.messages, false, false);
            if (typeof hasMoreMessages !== 'undefined') hasMoreMessages = data.has_more_before === true;
            if (typeof lastMessageId !== 'undefined' && data.messages.length) lastMessageId = data.messages[0].id;
            closeSearchModal();
            window.setTimeout(function () {
                if (sequence !== uxState.searchSequence || chatId !== activeChatId()) return;
                highlightMessage(document.querySelector('#messagesList [data-message-id="' + safeMessageId + '"]'));
            }, 0);
        }).catch(function (error) {
            if (error && error.name === 'AbortError') return;
            if (sequence !== uxState.searchSequence || chatId !== activeChatId()) return;
            console.error('Load message context error:', error);
            toast('That message could not be loaded. Try again.', 'error');
        }).finally(function () {
            if (sequence === uxState.searchSequence) {
                uxState.searchAbort = null;
                setSearchStatus('');
            }
        });
    };

    window.jumpToMessage = window.openMessageSearchResult;

    function setSearchContextReviewing(reviewing) {
        uxState.reviewingSearchContext = Boolean(reviewing);
        uxState.searchContextReviewStartedAt = uxState.reviewingSearchContext ? Date.now() : 0;
        if (!uxState.reviewingSearchContext) uxState.searchContextHasMoreAfter = false;
        window.pmSuppressNewMessageAutoScroll = uxState.reviewingSearchContext;
        window.pmReviewingSearchContext = uxState.reviewingSearchContext;
        const container = document.getElementById('messagesContainer');
        if (container) container.classList.toggle('reviewing-search-context', uxState.reviewingSearchContext);
    }

    window.exitSearchContextReview = function exitSearchContextReview() {
        const wasReviewing = uxState.reviewingSearchContext;
        setSearchContextReviewing(false);
        if (!wasReviewing) return;
        const chatId = activeChatId();
        if (!chatId) return;
        if (typeof window.cancelNewMessagePoll === 'function') window.cancelNewMessagePoll();
        if (typeof isInitialLoad !== 'undefined') isInitialLoad = true;
        if (typeof window.loadMessages === 'function') window.loadMessages(chatId);
    };

    function navigateSearchResults(delta) {
        if (!uxState.searchResults.length) return;
        uxState.searchIndex = (uxState.searchIndex + delta + uxState.searchResults.length) % uxState.searchResults.length;
        setSearchStatus(localized(
            'chat.search.position',
            {
                current: localizedNumber(uxState.searchIndex + 1),
                total: localizedNumber(uxState.searchResults.length)
            },
            localizedNumber(uxState.searchIndex + 1) + ' of ' + localizedNumber(uxState.searchResults.length)
        ), uxState.searchResults.length);
        window.openMessageSearchResult(uxState.searchResults[uxState.searchIndex]);
    }

    function dateKey(date) {
        return [date.getFullYear(), String(date.getMonth() + 1).padStart(2, '0'), String(date.getDate()).padStart(2, '0')].join('-');
    }

    function dateLabel(date) {
        const today = new Date();
        const yesterday = new Date(today.getFullYear(), today.getMonth(), today.getDate() - 1);
        if (dateKey(date) === dateKey(today)) return localized('date.today', {}, 'Today');
        if (dateKey(date) === dateKey(yesterday)) return localized('date.yesterday', {}, 'Yesterday');
        if (window.PmI18n && typeof window.PmI18n.formatDate === 'function') {
            return window.PmI18n.formatDate(date, {
                weekday: 'short', month: 'short', day: 'numeric',
                year: date.getFullYear() === today.getFullYear() ? undefined : 'numeric'
            });
        }
        return new Intl.DateTimeFormat(undefined, {
            weekday: 'short', month: 'short', day: 'numeric',
            year: date.getFullYear() === today.getFullYear() ? undefined : 'numeric'
        }).format(date);
    }

    function createTimelineMarker(kind, label, date) {
        const marker = document.createElement('div');
        marker.className = 'timeline-marker ' + (kind === 'unread' ? 'unread-divider' : 'date-divider');
        marker.setAttribute('role', 'separator');
        marker.setAttribute('aria-label', label);
        marker.setAttribute('aria-live', 'off');
        if (date) {
            const time = document.createElement('time');
            time.dateTime = date.toISOString();
            time.textContent = label;
            marker.appendChild(time);
        } else {
            marker.textContent = label;
        }
        return marker;
    }

    function decorateMessageTimeline() {
        if (uxState.timelineDecorating) return;
        const list = document.getElementById('messagesList');
        if (!list) return;
        uxState.timelineDecorating = true;
        list.querySelectorAll('.timeline-marker').forEach(function (marker) { marker.remove(); });
        let rows = Array.from(list.querySelectorAll(':scope > .message[data-message-id]'));
        const orderedRows = rows.slice().sort(function (first, second) {
            const firstDate = parseTimestamp(first.dataset.createdAt);
            const secondDate = parseTimestamp(second.dataset.createdAt);
            if (firstDate && secondDate && firstDate.getTime() !== secondDate.getTime()) {
                return firstDate.getTime() - secondDate.getTime();
            }
            return (positiveInteger(first.dataset.messageId) || 0) -
                (positiveInteger(second.dataset.messageId) || 0);
        });
        if (orderedRows.some(function (row, index) { return row !== rows[index]; })) {
            orderedRows.forEach(function (row) { list.appendChild(row); });
            rows = orderedRows;
        }
        let priorDate = '';
        let unreadInserted = false;
        rows.forEach(function (row) {
            const date = parseTimestamp(row.dataset.createdAt);
            if (date && dateKey(date) !== priorDate) {
                priorDate = dateKey(date);
                list.insertBefore(createTimelineMarker('date', dateLabel(date), date), row);
            }
            if (!unreadInserted && row.dataset.isUnread === 'true' && row.classList.contains('incoming')) {
                list.insertBefore(createTimelineMarker('unread', localizedLiteral('Unread messages')), row);
                unreadInserted = true;
            }
        });
        uxState.timelineDecorating = false;
        window.setTimeout(collectVisibleUnreadMessages, 80);
    }

    function messageIsVisible(row, container) {
        if (!row || !container || !row.isConnected) return false;
        const rowRect = row.getBoundingClientRect();
        const containerRect = container.getBoundingClientRect();
        if (containerRect.height <= 0 || rowRect.height <= 0) return false;
        const visibleTop = Math.max(rowRect.top, containerRect.top);
        const visibleBottom = Math.min(rowRect.bottom, containerRect.bottom);
        return visibleBottom - visibleTop >= Math.min(24, rowRect.height * 0.5);
    }

    function canAcknowledgeChat(chatId) {
        const content = document.getElementById('chatContent');
        const main = document.querySelector('.main-container');
        return positiveInteger(chatId) === activeChatId() && document.visibilityState === 'visible' &&
            (typeof document.hasFocus !== 'function' || document.hasFocus()) && content &&
            !content.classList.contains('d-none') && !content.inert &&
            content.getAttribute('aria-hidden') !== 'true' &&
            !(main && main.classList.contains('settings-mode')) &&
            !document.querySelector('.modal.show');
    }

    function readQueueFor(chatId) {
        let queue = uxState.readQueues.get(chatId);
        if (!queue) {
            queue = {ids: new Set(), timer: null, inFlight: false, retryCount: 0, forceRetry: false};
            uxState.readQueues.set(chatId, queue);
        }
        return queue;
    }

    function scheduleReadAcknowledgement(chatId, delay, forceRetry) {
        const queue = readQueueFor(chatId);
        const force = forceRetry === true || queue.forceRetry === true;
        if (queue.timer || queue.inFlight || !queue.ids.size || (!force && !canAcknowledgeChat(chatId))) return;
        queue.timer = window.setTimeout(function () {
            queue.timer = null;
            flushReadAcknowledgements(chatId, force);
        }, Math.max(0, Number(delay) || 0));
    }

    function retryPendingReadAcknowledgements() {
        uxState.readQueues.forEach(function (queue, chatId) {
            if (queue && queue.ids.size && canAcknowledgeChat(chatId)) {
                scheduleReadAcknowledgement(chatId, 0);
            }
        });
    }

    function collectVisibleUnreadMessages() {
        const chatId = activeChatId();
        if (!chatId || !canAcknowledgeChat(chatId)) return;
        const container = document.getElementById('messagesContainer');
        const content = document.getElementById('chatContent');
        if (!container || !content || content.classList.contains('d-none')) return;
        const queue = readQueueFor(chatId);
        let added = false;
        document.querySelectorAll('#messagesList .message.incoming[data-is-unread="true"][data-message-id]').forEach(function (row) {
            if (messageIsVisible(row, container)) {
                const id = positiveInteger(row.dataset.messageId);
                if (id && !queue.ids.has(id)) {
                    queue.ids.add(id);
                    added = true;
                }
            }
        });
        if (added) queue.retryCount = 0;
        scheduleReadAcknowledgement(chatId, 250);
    }

    function flushReadAcknowledgements(chatId, alreadyObserved) {
        const queue = uxState.readQueues.get(chatId);
        if (!queue) return;
        if (alreadyObserved) queue.forceRetry = true;
        const forceRetry = alreadyObserved === true || queue.forceRetry === true;
        if (queue.inFlight || (!forceRetry && !canAcknowledgeChat(chatId))) return;
        const ids = Array.from(queue.ids).slice(0, 100);
        if (!ids.length) return;
        if (queue.timer) {
            window.clearTimeout(queue.timer);
            queue.timer = null;
        }
        queue.inFlight = true;
        let retryDelay = 0;
        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        let timeoutId = null;
        const timeoutPromise = new Promise(function (_resolve, reject) {
            timeoutId = window.setTimeout(function () {
                if (controller) controller.abort();
                const error = new Error('Read acknowledgement timed out');
                error.name = 'TimeoutError';
                reject(error);
            }, 20000);
        });
        const request = window.fetch('api/chat.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            keepalive: true,
            signal: controller ? controller.signal : undefined,
            body: JSON.stringify({action: 'mark_messages_read', chat_id: chatId, message_ids: ids})
        }).then(function (response) {
            if (!response.ok) {
                const error = new Error('Read acknowledgement failed');
                const retryAfter = Number(response.headers && response.headers.get('Retry-After'));
                error.retryAfter = Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 0;
                throw error;
            }
            return response.json();
        });
        Promise.race([request, timeoutPromise]).then(function (data) {
            if (!data || data.success !== true) throw new Error('Read acknowledgement was rejected');
            ids.forEach(function (id) { queue.ids.delete(id); });
            queue.retryCount = 0;
            if (!queue.ids.size) queue.forceRetry = false;
            if (typeof window.loadChats === 'function') window.loadChats();
            if (chatId !== activeChatId()) return;
            ids.forEach(function (id) {
                const row = document.querySelector('#messagesList [data-message-id="' + id + '"]');
                if (row) row.dataset.isUnread = 'false';
            });
            decorateMessageTimeline();
        }).catch(function (error) {
            console.debug('Read acknowledgement error:', error);
            queue.retryCount += 1;
            if (queue.retryCount <= 5) {
                retryDelay = error.retryAfter || Math.min(30000, 1000 * Math.pow(2, queue.retryCount - 1));
            } else {
                queue.forceRetry = false;
            }
        }).finally(function () {
            if (timeoutId !== null) window.clearTimeout(timeoutId);
            queue.inFlight = false;
            if (!queue.ids.size) {
                if (queue.timer) window.clearTimeout(queue.timer);
                uxState.readQueues.delete(chatId);
            } else if (retryDelay) {
                scheduleReadAcknowledgement(chatId, retryDelay, forceRetry);
            } else if (queue.retryCount === 0) {
                scheduleReadAcknowledgement(chatId, 250);
            }
        });
    }

    function initializeEmojiPicker() {
        const grid = document.getElementById('emojiGrid');
        if (!grid || grid.childElementCount) return;
        grid.setAttribute('role', 'listbox');
        grid.setAttribute('aria-label', 'Emoji');
        EMOJI.forEach(function (emoji, index) {
            const button = document.createElement('button');
            button.type = 'button';
            button.className = 'emoji-option';
            button.textContent = emoji;
            button.dataset.emoji = emoji;
            button.dataset.search = index < 24 ? 'face smile emotion' :
                (index < 32 ? 'hand gesture' : index < 40 ? 'heart love' : 'celebration symbol');
            button.setAttribute('role', 'option');
            button.setAttribute('aria-selected', 'false');
            button.setAttribute('aria-label', 'Insert ' + emoji);
            button.tabIndex = index === 0 ? 0 : -1;
            grid.appendChild(button);
        });
        grid.addEventListener('keydown', function (event) {
            const buttons = Array.from(grid.querySelectorAll('.emoji-option:not([hidden])'));
            const index = buttons.indexOf(document.activeElement);
            if (index < 0) return;
            let columns = 0;
            if (typeof window.getComputedStyle === 'function') {
                const template = window.getComputedStyle(grid).gridTemplateColumns.trim();
                if (template && template !== 'none') columns = template.split(/\s+/).length;
            }
            if (!columns) {
                columns = window.matchMedia && window.matchMedia('(max-width: 420px)').matches ? 5 :
                    (window.matchMedia && window.matchMedia('(max-width: 768px)').matches ? 6 : 7);
            }
            const movement = {ArrowRight: 1, ArrowLeft: -1, ArrowDown: columns, ArrowUp: -columns}[event.key];
            if (!movement) return;
            event.preventDefault();
            const target = buttons[(index + movement + buttons.length) % buttons.length];
            buttons.forEach(function (button) {
                button.tabIndex = button === target ? 0 : -1;
                button.setAttribute('aria-selected', button === target ? 'true' : 'false');
            });
            target.focus();
        });
    }

    function closeEmojiPicker(restoreFocus) {
        const picker = document.getElementById('emojiPicker');
        const button = document.querySelector('[data-pm-action="emoji-picker"]');
        if (!picker) return;
        picker.hidden = true;
        picker.classList.remove('show');
        if (button) button.setAttribute('aria-expanded', 'false');
        if (restoreFocus) {
            const input = document.getElementById('messageInput');
            if (input) input.focus({preventScroll: true});
        }
    }

    function toggleEmojiPicker() {
        const picker = document.getElementById('emojiPicker');
        const button = document.querySelector('[data-pm-action="emoji-picker"]');
        if (!picker) return;
        const opening = picker.hidden || !picker.classList.contains('show');
        picker.hidden = !opening;
        picker.classList.toggle('show', opening);
        if (button) button.setAttribute('aria-expanded', opening ? 'true' : 'false');
        if (opening) {
            initializeEmojiPicker();
            const first = picker.querySelector('.emoji-option:not([hidden])');
            if (first) {
                picker.querySelectorAll('.emoji-option').forEach(function (option) {
                    option.tabIndex = option === first ? 0 : -1;
                    option.setAttribute('aria-selected', option === first ? 'true' : 'false');
                });
                first.focus({preventScroll: true});
            }
        }
    }

    function insertEmoji(value) {
        const input = document.getElementById('messageInput');
        if (!input || !EMOJI.includes(value)) return;
        const start = Number.isInteger(input.selectionStart) ? input.selectionStart : input.value.length;
        const end = Number.isInteger(input.selectionEnd) ? input.selectionEnd : start;
        input.setRangeText(value, start, end, 'end');
        input.dispatchEvent(new Event('input', {bubbles: true}));
        closeEmojiPicker(true);
    }

    function filterEmoji(query) {
        const needle = String(query || '').trim().toLowerCase();
        const buttons = Array.from(document.querySelectorAll('#emojiGrid .emoji-option'));
        buttons.forEach(function (button) {
            button.hidden = Boolean(needle && button.dataset.emoji !== needle &&
                !String(button.dataset.search || '').includes(needle));
        });
        const first = buttons.find(function (button) { return !button.hidden; });
        buttons.forEach(function (button) {
            button.tabIndex = button === first ? 0 : -1;
            button.setAttribute('aria-selected', button === first ? 'true' : 'false');
        });
        const grid = document.getElementById('emojiGrid');
        if (grid) grid.setAttribute('aria-label', first ? 'Emoji choices' : 'No matching emoji');
        const focused = document.activeElement;
        if (first && focused && focused.classList && focused.classList.contains('emoji-option') && focused.hidden) {
            first.focus({preventScroll: true});
        }
    }

    function recorderSupport() {
        return Boolean(window.isSecureContext && navigator.mediaDevices &&
            typeof navigator.mediaDevices.getUserMedia === 'function' && typeof window.MediaRecorder === 'function');
    }

    function preferredRecordingMime() {
        const candidates = ['audio/webm;codecs=opus', 'audio/mp4', 'audio/ogg;codecs=opus', 'audio/webm'];
        if (!window.MediaRecorder || typeof MediaRecorder.isTypeSupported !== 'function') return '';
        return candidates.find(function (candidate) { return MediaRecorder.isTypeSupported(candidate); }) || '';
    }

    function recordingExtension(mime) {
        const type = normalizedMime(mime);
        if (type === 'audio/mp4') return 'm4a';
        if (type === 'audio/ogg') return 'ogg';
        return 'webm';
    }

    function stopVoiceTracks(session) {
        if (!session || !session.stream) return;
        session.stream.getTracks().forEach(function (track) { track.stop(); });
        session.stream = null;
    }

    function clearVoiceTimer(session) {
        if (session && session.timer) window.clearInterval(session.timer);
        if (session) session.timer = null;
    }

    function releaseVoiceObjectUrl() {
        if (uxState.voice.objectUrl) URL.revokeObjectURL(uxState.voice.objectUrl);
        uxState.voice.objectUrl = null;
    }

    function formatDuration(milliseconds) {
        const seconds = Math.max(0, Math.floor(milliseconds / 1000));
        return Math.floor(seconds / 60) + ':' + String(seconds % 60).padStart(2, '0');
    }

    function updateVoiceUi() {
        const mode = uxState.voice.mode;
        const session = uxState.voice.session;
        const status = document.getElementById('voiceRecordingStatus');
        const preview = document.getElementById('voicePreview');
        const recordingShell = document.querySelector('.voice-recording-shell');
        const composer = document.querySelector('.message-input-container');
        if (composer) {
            composer.classList.toggle('is-recording',
                mode === 'requesting' || mode === 'recording' || mode === 'processing');
            composer.classList.toggle('has-voice-preview', mode === 'preview');
        }
        if (status) {
            status.hidden = mode !== 'requesting' && mode !== 'recording' && mode !== 'processing';
            status.classList.toggle('show', !status.hidden);
            if (mode === 'requesting') {
                status.textContent = localized('composer.voice_requesting', {}, 'Requesting microphone…');
            }
            if (mode === 'recording' && session) {
                const time = formatDuration(Date.now() - session.startedAt);
                status.textContent = localized('composer.voice_recording', {time: time}, 'Recording ' + time);
            }
            if (mode === 'processing') {
                status.textContent = localized('composer.voice_preparing', {}, 'Preparing voice message…');
            }
        }
        if (recordingShell) {
            recordingShell.hidden = mode !== 'requesting' && mode !== 'recording' && mode !== 'processing';
        }
        if (preview) {
            preview.hidden = mode !== 'preview';
            preview.classList.toggle('show', mode === 'preview');
        }
        syncComposerControls();
    }

    function clearVoicePreview() {
        releaseVoiceObjectUrl();
        uxState.voice.file = null;
        uxState.voice.sourceChatId = null;
        const audio = document.getElementById('voicePreviewAudio');
        if (audio) {
            audio.removeAttribute('src');
            audio.load();
        }
    }

    function abandonVoiceSession(session) {
        if (!session) return;
        session.cancelled = true;
        clearVoiceTimer(session);
        if (session.recorder && session.recorder.state !== 'inactive') {
            try {
                session.recorder.stop();
            } catch (error) {
                console.debug('Voice recorder was already stopping:', error);
            }
        }
        stopVoiceTracks(session);
    }

    function resetVoiceState() {
        const session = uxState.voice.session;
        uxState.voice.session = null;
        abandonVoiceSession(session);
        clearVoicePreview();
        uxState.voice.mode = 'idle';
        updateVoiceUi();
    }

    function cancelVoiceRecording() {
        uxState.voice.requestToken += 1;
        resetVoiceState();
    }

    function finishVoiceRecording() {
        const session = uxState.voice.session;
        if (!session || session.finishing || !session.recorder || session.recorder.state === 'inactive') return;
        session.finishing = true;
        clearVoiceTimer(session);
        uxState.voice.mode = 'processing';
        updateVoiceUi();
        session.recorder.stop();
    }

    function beginVoiceRecording() {
        if (!recorderSupport()) {
            toast('Voice recording is not supported in this browser or connection.', 'warning');
            return;
        }
        const sourceChatId = activeChatId();
        if (!sourceChatId) {
            toast('Select a conversation before recording.', 'warning');
            return;
        }
        const input = document.getElementById('messageInput');
        if ((input && (input.value.trim() || input.dataset.editMessageId)) ||
            (typeof currentAttachment !== 'undefined' && currentAttachment)) {
            toast('Send or clear the current message before recording a voice message.', 'warning');
            syncComposerControls();
            return;
        }
        if (uxState.voice.mode !== 'idle') return;
        const token = ++uxState.voice.requestToken;
        const session = {
            token: token,
            sourceChatId: sourceChatId,
            stream: null,
            recorder: null,
            chunks: [],
            totalBytes: 0,
            startedAt: 0,
            timer: null,
            cancelled: false,
            finishing: false
        };
        uxState.voice.session = session;
        uxState.voice.mode = 'requesting';
        updateVoiceUi();
        navigator.mediaDevices.getUserMedia({audio: true}).then(function (stream) {
            if (token !== uxState.voice.requestToken || uxState.voice.session !== session ||
                uxState.voice.mode !== 'requesting') {
                stream.getTracks().forEach(function (track) { track.stop(); });
                return;
            }
            const mime = preferredRecordingMime();
            let recorder;
            try {
                recorder = mime ? new MediaRecorder(stream, {mimeType: mime}) : new MediaRecorder(stream);
            } catch (error) {
                stream.getTracks().forEach(function (track) { track.stop(); });
                throw error;
            }
            session.stream = stream;
            session.recorder = recorder;
            recorder.addEventListener('dataavailable', function (event) {
                if (uxState.voice.session !== session || token !== uxState.voice.requestToken ||
                    session.cancelled || !event.data || event.data.size <= 0) return;
                session.chunks.push(event.data);
                session.totalBytes += event.data.size;
                if (session.totalBytes > MAX_RECORDING_BYTES) {
                    toast('The recording exceeded 50 MB and was cancelled.', 'error');
                    cancelVoiceRecording();
                }
            });
            recorder.addEventListener('stop', function () {
                clearVoiceTimer(session);
                stopVoiceTracks(session);
                if (uxState.voice.session !== session || token !== uxState.voice.requestToken || session.cancelled) {
                    return;
                }
                if (!session.chunks.length) {
                    toast('The recording was empty. Please try again.', 'warning');
                    resetVoiceState();
                    return;
                }
                const type = normalizedMime(recorder.mimeType || session.chunks[0].type) || 'audio/webm';
                const blob = new Blob(session.chunks, {type: type});
                if (!blob.size || blob.size > MAX_RECORDING_BYTES) {
                    toast('The recording could not be prepared safely.', 'error');
                    resetVoiceState();
                    return;
                }
                const file = new File([blob], 'voice-' + Date.now() + '.' + recordingExtension(type), {
                    type: type,
                    lastModified: Date.now()
                });
                uxState.voice.session = null;
                uxState.voice.file = file;
                uxState.voice.sourceChatId = session.sourceChatId;
                releaseVoiceObjectUrl();
                uxState.voice.objectUrl = URL.createObjectURL(blob);
                const audio = document.getElementById('voicePreviewAudio');
                if (audio) audio.src = uxState.voice.objectUrl;
                uxState.voice.mode = 'preview';
                updateVoiceUi();
            }, {once: true});
            recorder.addEventListener('error', function () {
                if (uxState.voice.session !== session || token !== uxState.voice.requestToken) return;
                toast('Recording stopped because the microphone became unavailable.', 'error');
                cancelVoiceRecording();
            });
            recorder.start(1000);
            session.startedAt = Date.now();
            uxState.voice.mode = 'recording';
            session.timer = window.setInterval(function () {
                if (uxState.voice.session !== session || token !== uxState.voice.requestToken) {
                    clearVoiceTimer(session);
                    return;
                }
                if (Date.now() - session.startedAt >= MAX_RECORDING_MS) finishVoiceRecording();
                updateVoiceUi();
            }, 500);
            updateVoiceUi();
        }).catch(function (error) {
            if (token !== uxState.voice.requestToken || uxState.voice.session !== session) return;
            console.debug('Microphone request failed:', error);
            resetVoiceState();
            toast('Microphone access was not granted. You can still attach an audio file.', 'warning');
        });
    }

    function sendVoiceRecording() {
        const file = uxState.voice.file;
        const sourceChatId = positiveInteger(uxState.voice.sourceChatId);
        if (!(file instanceof File) || uxState.voice.mode !== 'preview') return;
        if (typeof window.handleFileSelect !== 'function' || typeof window.sendMessage !== 'function') return;
        if (!sourceChatId || sourceChatId !== activeChatId()) {
            toast('This voice preview belongs to another conversation and was discarded.', 'warning');
            cancelVoiceRecording();
            return;
        }
        uxState.voice.requestToken += 1;
        resetVoiceState();
        window.handleFileSelect({target: {files: [file], value: ''}});
        window.setTimeout(function () {
            if (sourceChatId !== activeChatId() ||
                typeof currentAttachment === 'undefined' || currentAttachment !== file) {
                if (typeof currentAttachment !== 'undefined' && currentAttachment === file &&
                    typeof window.clearAttachment === 'function') window.clearAttachment();
                toast('The voice message was not sent because the conversation changed.', 'warning');
                return;
            }
            window.sendMessage();
        }, 0);
    }

    function syncComposerControls() {
        const input = document.getElementById('messageInput');
        const voiceButton = document.querySelector('[data-pm-action="voice-record"]');
        const sendButton = document.querySelector('.send-btn[data-pm-action="send-message"], .send-btn');
        const hasText = Boolean(input && input.value.trim());
        const hasAttachment = typeof currentAttachment !== 'undefined' && currentAttachment instanceof File;
        const supported = recorderSupport();
        const voiceBusy = uxState.voice.mode !== 'idle';
        const composer = document.querySelector('.message-input-container');
        window.pmVoiceComposerBusy = voiceBusy;
        document.documentElement.classList.toggle('voice-recording-supported', supported);
        if (voiceButton) voiceButton.hidden = !supported || hasText || hasAttachment || voiceBusy || !activeChatId();
        if (voiceButton) voiceButton.setAttribute('aria-pressed', voiceBusy ? 'true' : 'false');
        if (sendButton) sendButton.hidden = supported && (voiceBusy || (!hasText && !hasAttachment && Boolean(activeChatId())));
        if (composer) {
            composer.classList.toggle('has-sendable-content', hasText || hasAttachment);
            composer.querySelectorAll('.composer-shell button:not(.voice-trigger)').forEach(function (button) {
                if (voiceBusy && !button.disabled) {
                    button.disabled = true;
                    button.dataset.voiceLocked = 'true';
                } else if (!voiceBusy && button.dataset.voiceLocked === 'true') {
                    button.disabled = false;
                    delete button.dataset.voiceLocked;
                }
            });
        }
        if (input) {
            if (voiceBusy && !input.readOnly) {
                input.readOnly = true;
                input.dataset.voiceLocked = 'true';
            } else if (!voiceBusy && input.dataset.voiceLocked === 'true') {
                input.readOnly = false;
                delete input.dataset.voiceLocked;
            }
        }
    }

    function setupChatRowPreferenceGestures() {
        const list = document.getElementById('chatList');
        if (!list) return;
        let pendingGesture = null;

        const cancelPendingGesture = function () {
            if (pendingGesture && pendingGesture.timer) window.clearTimeout(pendingGesture.timer);
            pendingGesture = null;
        };

        list.addEventListener('contextmenu', function (event) {
            const row = event.target.closest && event.target.closest('.chat-item[data-chat-id]');
            if (!row || row.parentElement !== list || event.target.closest('#chatRowMenu')) return;
            event.preventDefault();
            openChatRowMenu(row.dataset.chatId, row, {x: event.clientX, y: event.clientY});
        });

        list.addEventListener('pointerdown', function (event) {
            if (!['touch', 'pen'].includes(event.pointerType) || event.button !== 0) return;
            const row = event.target.closest && event.target.closest('.chat-item[data-chat-id]');
            if (!row || row.parentElement !== list || event.target.closest('#chatRowMenu')) return;
            cancelPendingGesture();
            pendingGesture = {
                row: row,
                pointerId: event.pointerId,
                x: event.clientX,
                y: event.clientY,
                timer: window.setTimeout(function () {
                    if (!pendingGesture || pendingGesture.row !== row) return;
                    row.dataset.suppressNextClick = 'true';
                    window.setTimeout(function () {
                        if (row.dataset.suppressNextClick === 'true') {
                            delete row.dataset.suppressNextClick;
                        }
                    }, 1500);
                    openChatRowMenu(row.dataset.chatId, row, {
                        x: pendingGesture.x,
                        y: pendingGesture.y
                    });
                    pendingGesture = null;
                }, 550)
            };
        }, {passive: true});

        list.addEventListener('pointermove', function (event) {
            if (!pendingGesture || pendingGesture.pointerId !== event.pointerId) return;
            if (Math.abs(event.clientX - pendingGesture.x) > 10 ||
                Math.abs(event.clientY - pendingGesture.y) > 10) cancelPendingGesture();
        }, {passive: true});
        ['pointerup', 'pointercancel', 'lostpointercapture'].forEach(function (name) {
            list.addEventListener(name, cancelPendingGesture, {passive: true});
        });
    }

    const legacyRenderChats = window.renderChats;
    window.renderChats = function renderChatsWithTelegramStates() {
        const result = legacyRenderChats.apply(this, arguments);
        decorateConversationRows();
        refreshProtectedBanner();
        return result;
    };

    const legacyRenderMessages = window.renderMessages;
    window.renderMessages = function renderMessagesWithTimeline() {
        const isPrepend = arguments[1] === true;
        const result = legacyRenderMessages.apply(this, arguments);
        const scrollContainer = isPrepend ? document.getElementById('messagesContainer') : null;
        const heightBeforeDecoration = scrollContainer ? scrollContainer.scrollHeight : 0;
        const scrollTopBeforeDecoration = scrollContainer ? scrollContainer.scrollTop : 0;
        decorateMessageTimeline();
        if (scrollContainer) {
            const markerHeightDelta = scrollContainer.scrollHeight - heightBeforeDecoration;
            if (markerHeightDelta) {
                scrollContainer.scrollTop = scrollTopBeforeDecoration + markerHeightDelta;
            }
        }
        return result;
    };

    const legacySelectChat = window.selectChat;
    window.selectChat = function selectChatWithUxLifecycle(chatId) {
        const nextChatId = positiveInteger(chatId);
        const priorChatId = activeChatId();
        if (nextChatId !== priorChatId) window.cleanupTransientChatUx();
        const result = legacySelectChat.apply(this, arguments);
        window.setTimeout(function () {
            decorateConversationRows();
        refreshProtectedBanner();
            decorateMessageTimeline();
            syncComposerControls();
        }, 0);
        return result;
    };

    window.cleanupTransientChatUx = function cleanupTransientChatUx() {
        const chatId = activeChatId();
        const queue = chatId ? uxState.readQueues.get(chatId) : null;
        if (queue && queue.ids.size) {
            queue.forceRetry = true;
            if (!queue.inFlight) flushReadAcknowledgements(chatId, true);
        }
        cancelChatSearch();
        setSearchContextReviewing(false);
        window.closeChatSidePanel(false);
        cancelVoiceRecording();
        closeEmojiPicker(false);
        closeChatRowMenu(false);
        if (typeof window.stopActiveTyping === 'function') window.stopActiveTyping();
        if (typeof window.cancelActiveMessageLoad === 'function') {
            window.cancelActiveMessageLoad();
        }
        if (typeof window.cancelNewMessagePoll === 'function') {
            window.cancelNewMessagePoll();
        }
    };

    ['logout'].forEach(function (name) {
        const legacy = window[name];
        if (typeof legacy !== 'function') return;
        window[name] = function closeTransientChatUx() {
            window.cleanupTransientChatUx();
            return legacy.apply(this, arguments);
        };
    });

    window.addEventListener('pm:send-state', function (event) {
        const detail = event.detail || {};
        const chatId = positiveInteger(detail.chatId);
        const attemptId = String(detail.attemptId || 'unscoped');
        if (!chatId || !['sending', 'sent', 'rejected', 'unconfirmed'].includes(detail.state)) return;
        let entry = uxState.delivery.get(chatId);
        if (!entry) {
            entry = {active: null, unconfirmed: new Set()};
            uxState.delivery.set(chatId, entry);
        }
        if (detail.state === 'sending') {
            entry.active = attemptId;
        } else if (detail.state === 'unconfirmed') {
            if (entry.active === attemptId) entry.active = null;
            entry.unconfirmed.add(attemptId);
        } else if (detail.state === 'sent') {
            if (entry.active === attemptId) entry.active = null;
            entry.unconfirmed.delete(attemptId);
        } else {
            if (entry.active === attemptId) entry.active = null;
        }
        if (!entry.active && !entry.unconfirmed.size) {
            uxState.delivery.delete(chatId);
        }
        decorateConversationRows();
        refreshProtectedBanner();
        syncComposerControls();
    });

    function handleActionClick(event) {
        const actionElement = event.target.closest && event.target.closest('[data-pm-action]');
        if (!actionElement) return;
        const action = actionElement.dataset.pmAction;
        const uxActions = [
            'emoji-picker', 'emoji-picker-close', 'voice-record', 'voice-preview', 'voice-cancel',
            'voice-send', 'side-panel-close', 'side-panel-search', 'side-panel-info',
            'chat-side-search-prev', 'chat-side-search-next', 'chat-side-search-clear',
            'chat-pref-pin', 'chat-pref-mute', 'chat-pref-selected-pin', 'chat-pref-selected-mute'
        ];
        if (uxActions.includes(action)) event.preventDefault();
        if (action === 'emoji-picker') toggleEmojiPicker();
        if (action === 'emoji-picker-close') closeEmojiPicker(true);
        if (action === 'voice-record') beginVoiceRecording();
        if (action === 'voice-preview') finishVoiceRecording();
        if (action === 'voice-cancel') cancelVoiceRecording();
        if (action === 'voice-send') sendVoiceRecording();
        if (action === 'side-panel-close') window.closeChatSidePanel(true);
        if (action === 'side-panel-search') {
            window.openChatSidePanel('search');
            const input = document.getElementById('chatSideSearchInput');
            if (input) input.focus();
        }
        if (action === 'side-panel-info') window.showChatInfo();
        if (action === 'chat-side-search-prev') navigateSearchResults(-1);
        if (action === 'chat-side-search-next') navigateSearchResults(1);
        if (action === 'chat-side-search-clear') {
            const input = document.getElementById('chatSideSearchInput');
            if (input) {
                input.value = '';
                window.searchInChat(input);
                input.focus();
            }
        }
        if (action === 'chat-pref-pin') toggleChatPreference('pin');
        if (action === 'chat-pref-mute') toggleChatPreference('mute');
        if (action === 'chat-pref-selected-pin') toggleChatPreference('pin', activeChatId());
        if (action === 'chat-pref-selected-mute') toggleChatPreference('mute', activeChatId());
        if (action !== 'emoji-picker' && !actionElement.closest('#emojiPicker')) closeEmojiPicker(false);
    }

    document.addEventListener('click', handleActionClick);
    document.addEventListener('click', function (event) {
        const picker = document.getElementById('emojiPicker');
        const option = event.target.closest && event.target.closest('.emoji-option[data-emoji]');
        if (option) {
            insertEmoji(option.dataset.emoji);
            return;
        }
        if (picker && !picker.hidden && !event.target.closest('#emojiPicker') &&
            !event.target.closest('[data-pm-action="emoji-picker"]')) closeEmojiPicker(false);
        const menu = document.getElementById('chatRowMenu');
        if (menu && !menu.hidden && !event.target.closest('#chatRowMenu') &&
            !event.target.closest('.chat-row-menu-button')) closeChatRowMenu(false);
    });

    document.addEventListener('keydown', function (event) {
        if (event.key === 'Escape') {
            closeEmojiPicker(true);
            closeChatRowMenu(true);
            if (document.getElementById('chatContent') &&
                document.getElementById('chatContent').classList.contains('side-panel-open')) {
                window.closeChatSidePanel(true);
            }
        }
        const row = event.target.closest && event.target.closest('.chat-item[data-chat-id]');
        if (row && event.shiftKey && event.key === 'F10') {
            event.preventDefault();
            openChatRowMenu(row.dataset.chatId, row);
        }
        const menu = event.target.closest && event.target.closest('#chatRowMenu');
        if (menu && ['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(event.key)) {
            const items = Array.from(menu.querySelectorAll('[role^="menuitem"]'));
            const current = items.indexOf(document.activeElement);
            let next = current;
            if (event.key === 'Home') next = 0;
            if (event.key === 'End') next = items.length - 1;
            if (event.key === 'ArrowDown') next = (current + 1 + items.length) % items.length;
            if (event.key === 'ArrowUp') next = (current - 1 + items.length) % items.length;
            if (items[next]) {
                event.preventDefault();
                items[next].focus();
            }
        }
        const panelTab = event.target.closest && event.target.closest('[data-chat-panel-view]');
        if (panelTab && ['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key)) {
            const tabs = Array.from(document.querySelectorAll('[data-chat-panel-view]'));
            const current = tabs.indexOf(panelTab);
            let next = current;
            if (event.key === 'Home') next = 0;
            if (event.key === 'End') next = tabs.length - 1;
            if (event.key === 'ArrowRight') next = (current + 1) % tabs.length;
            if (event.key === 'ArrowLeft') next = (current - 1 + tabs.length) % tabs.length;
            if (tabs[next]) {
                event.preventDefault();
                tabs[next].focus();
                tabs[next].click();
            }
        }
    });

    const input = document.getElementById('messageInput');
    if (input) {
        input.addEventListener('input', function () {
            decorateConversationRows();
        refreshProtectedBanner();
            syncComposerControls();
        });
    }

    const chatList = document.getElementById('chatList');
    if (chatList) chatList.addEventListener('hi:conversation-row-states-refreshed', decorateConversationRows);

    const emojiSearch = document.getElementById('emojiSearchInput');
    if (emojiSearch) emojiSearch.addEventListener('input', function () { filterEmoji(emojiSearch.value); });

    const messagesContainer = document.getElementById('messagesContainer');
    if (messagesContainer) messagesContainer.addEventListener('scroll', function () {
        collectVisibleUnreadMessages();
        const distanceFromBottom = messagesContainer.scrollHeight -
            messagesContainer.scrollTop - messagesContainer.clientHeight;
        if (distanceFromBottom <= 80 && uxState.reviewingSearchContext &&
            !uxState.searchContextHasMoreAfter &&
            Date.now() - uxState.searchContextReviewStartedAt > 600) {
            window.exitSearchContextReview();
        }
    }, {passive: true});
    document.addEventListener('visibilitychange', function () {
        collectVisibleUnreadMessages();
        retryPendingReadAcknowledgements();
    });
    window.addEventListener('focus', function () {
        collectVisibleUnreadMessages();
        retryPendingReadAcknowledgements();
    });
    window.addEventListener('online', function () {
        uxState.readQueues.forEach(function (queue, chatId) {
            if (!queue || !queue.ids.size) return;
            queue.retryCount = 0;
            queue.forceRetry = true;
            scheduleReadAcknowledgement(chatId, 0, true);
        });
    });
    document.addEventListener('hidden.bs.modal', function () {
        window.setTimeout(function () {
            collectVisibleUnreadMessages();
            retryPendingReadAcknowledgements();
        }, 0);
    });
    window.addEventListener('resize', function () {
        if (!widePanelAvailable()) {
            const panel = document.getElementById('chatSidePanel');
            window.closeChatSidePanel(Boolean(panel && panel.contains(document.activeElement)));
            const menu = document.getElementById('chatRowMenu');
            const menuHadFocus = Boolean(menu && menu.contains(document.activeElement));
            const menuTrigger = menu && menu.__pmTrigger;
            closeChatRowMenu(false);
            if (menuHadFocus) {
                window.setTimeout(function restoreFocusAfterMenuBreakpoint() {
                    const main = document.querySelector('.main-container');
                    const chatContent = document.getElementById('chatContent');
                    const settingsContent = document.getElementById('settingsContent');
                    let target = null;
                    if (window.innerWidth <= 768 && main && main.classList.contains('settings-detail-mode')) {
                        target = settingsContent && settingsContent.querySelector('.settings-back-btn, button, [tabindex]');
                    } else if (window.innerWidth <= 768 && chatContent &&
                        !chatContent.classList.contains('d-none')) {
                        target = document.querySelector('.mobile-chat-back button') ||
                            document.getElementById('messageInput');
                    } else if (menuTrigger && menuTrigger.isConnected && !menuTrigger.closest('[inert]')) {
                        target = menuTrigger;
                    } else {
                        target = document.querySelector('#chatSearch, .sidebar input[type="search"]');
                    }
                    if (target) target.focus({preventScroll: true});
                }, 0);
            }
        }
        collectVisibleUnreadMessages();
        syncComposerControls();
    });
    window.addEventListener('pm:attachment-state-change', syncComposerControls);
    window.refreshLocalizedChatUx = function refreshLocalizedChatUx() {
        decorateConversationRows();
        refreshProtectedBanner();
        decorateMessageTimeline();
        updateSelectedChatPreferenceLabels();
        const searchView = document.getElementById('chatSidePanelSearchView');
        const panel = document.getElementById('chatSidePanel');
        if (panel && !panel.hidden) {
            setSidePanelView(searchView && !searchView.hidden ? 'search' : 'info');
        }
        if (uxState.searchResults.length && uxState.searchIndex >= 0) {
            setSearchStatus(localized(
                'chat.search.position',
                {
                    current: localizedNumber(uxState.searchIndex + 1),
                    total: localizedNumber(uxState.searchResults.length)
                },
                localizedNumber(uxState.searchIndex + 1) + ' of ' + localizedNumber(uxState.searchResults.length)
            ), uxState.searchResults.length);
        } else if (Number.isSafeInteger(uxState.completedSearchCount)) {
            refreshSearchCountOutput(uxState.completedSearchCount);
        }
        updateVoiceUi();
        syncComposerControls();
    };
    window.addEventListener('pagehide', function () {
        uxState.readQueues.forEach(function (queue, chatId) {
            if (!queue || !queue.ids.size) return;
            queue.forceRetry = true;
            if (!queue.inFlight) flushReadAcknowledgements(chatId, true);
        });
        cancelChatSearch();
        cancelVoiceRecording();
        if (typeof window.releaseAttachmentPreviewObjectUrl === 'function') {
            window.releaseAttachmentPreviewObjectUrl();
        }
    });

    const searchModal = document.getElementById('chatSearchModal');
    if (searchModal) searchModal.addEventListener('hidden.bs.modal', cancelChatSearch);
    setupChatRowPreferenceGestures();
    initializeEmojiPicker();
    syncComposerControls();
}());
