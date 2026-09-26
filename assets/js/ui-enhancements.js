(function () {
    'use strict';

    if (window.pmSecurityHardeningReady !== true) {
        console.error('Required security hardening is unavailable; UI enhancements were not initialized.');
        return;
    }

    const state = {
        conversationFilter: 'all',
        currentView: 'chats',
        activeChatKey: '',
        focusedChatKey: '',
        chatSelectionEpoch: 0,
        themeRequestId: 0
    };

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

    function localeCaseFold(value) {
        const locale = window.PmI18n && typeof window.PmI18n.getLocale === 'function'
            ? window.PmI18n.getLocale()
            : undefined;
        try {
            return String(value || '').toLocaleLowerCase(locale);
        } catch (error) {
            return String(value || '').toLowerCase();
        }
    }

    window.toggleAppTheme = function toggleAppTheme() {
        const isLight = !document.body.classList.contains('light-mode');
        const theme = isLight ? 'light' : 'dark';
        const requestId = ++state.themeRequestId;

        applyThemePreference(theme);
        if (window.userSettings) {
            window.userSettings.theme = theme;
        }

        fetch('api/settings.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({
                action: 'update_settings',
                settings: {theme: theme}
            })
        })
            .then(function (response) {
                if (!response.ok) {
                    throw new Error('Theme preference could not be saved');
                }
                return response.json();
            })
            .then(function (result) {
                if (!result.success) {
                    throw new Error(result.message || 'Theme preference could not be saved');
                }
                if (requestId === state.themeRequestId) {
                    applyThemePreference(theme);
                    if (typeof window.showToast === 'function') {
                        window.showToast('Theme preference saved', 'success', 2400);
                    }
                }
            })
            .catch(function (error) {
                console.warn(error.message);
                if (requestId === state.themeRequestId && typeof window.showToast === 'function') {
                    window.showToast('Theme changed on this device, but could not sync', 'warning', 4200);
                }
            });
    };

    function applyThemePreference(theme) {
        const isLight = theme === 'light';
        document.body.classList.toggle('light-mode', isLight);
        localStorage.setItem('lightMode', String(isLight));
    }

    const ready = (callback) => {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', callback, {once: true});
        } else {
            callback();
        }
    };

    ready(function initializeUiEnhancements() {
        const chatList = document.getElementById('chatList');
        const sidebar = document.getElementById('sidebar');
        const settingsList = document.getElementById('settingsList');
        const settingsContent = document.getElementById('settingsContent');
        const settingsOverview = document.getElementById('settingsOverview');
        const messagesList = document.getElementById('messagesList');
        const messagesContainer = document.getElementById('messagesContainer');
        const settingsContentArea = document.getElementById('settingsContentArea');
        const searchInput = document.getElementById('searchInput');
        const searchClear = document.getElementById('searchClear');
        const searchShortcut = document.querySelector('.search-shell kbd');
        const mainContainer = document.querySelector('.main-container');
        const chatContent = document.getElementById('chatContent');
        const welcomeScreen = document.getElementById('welcomeScreen');
        const mobileBottomNav = document.getElementById('mobileBottomNav');
        const sidebarOverlay = document.getElementById('sidebarOverlay');
        const filterButtons = Array.from(document.querySelectorAll('[data-conversation-filter]'));
        let lastSendSucceeded = null;
        let sentDraft = '';
        let queuedDraft = '';
        let sendChatKey = '';
        let contextMenuOpener = null;
        let lastSettingsOpener = null;
        let selectedChatElement = null;
        let editInFlight = false;
        let editRequestId = 0;
        let draftBeforeEdit = '';
        let settingsReturnSurface = 'welcome';
        let settingsEntryOpener = null;
        const settingsHistorySession = 'hi-settings-' + Date.now().toString(36) + '-' +
            Math.random().toString(36).slice(2, 8);
        let settingsHistorySyncing = false;
        let settingsHistorySyncTimer = 0;
        let settingsModalHistorySyncing = false;
        let settingsModalHistorySyncTimer = 0;
        let settingsResizeTimer = 0;
        const appHistorySession = 'hi-app-' + Date.now().toString(36) + '-' +
            Math.random().toString(36).slice(2, 8);
        let appHistoryRestoring = false;
        let pendingHistoryChatId = '';
        let pendingHistoryRestoreChatId = '';
        let pendingHistoryChatTimer = 0;
        let messageLogReadyTimer = 0;
        const settingsSections = ['profile', 'account', 'notifications', 'privacy', 'appearance', 'storage', 'about'];
        let lastSettingsSection = localStorage.getItem('hi.settings.section') || 'profile';
        const chatDrafts = new Map();
        const modalOpeners = new WeakMap();
        const failedAvatarUrls = new Set();
        const avatarContainerSelector = '.chat-avatar, .sender-avatar, .user-profile-avatar, ' +
            '.profile-avatar-large, .participant-avatar';
        let activeModalElement = null;
        let activeModalOpening = false;
        let jumpButton;

        if (!chatList || !settingsList || !messagesList || !searchInput) {
            return;
        }
        if (!settingsSections.includes(lastSettingsSection)) {
            lastSettingsSection = 'profile';
        }

        state.currentView = getCurrentView();
        setupSurfaceCoordinator();
        setupChatListKeyboardNavigation();
        setupReliableDropdowns();
        setupChatIdentityTagging();
        setupRequestScoping();
        setupThemeControls();
        setupSearch();
        setupPeopleSearch();
        setupLoadingFallback();
        setupJumpToLatest();
        setupSendFeedback();
        setupComposerSafety();
        setupFileDropValidation();
        setupModalSafety();
        setupAvatarFallbacks();
        setupImageAttachmentFallbacks();
        setupAccessibility();
        enhanceInteractiveElements(document);
        enhanceMessageActions(document);
        enhancePasswordFields(document);
        enhanceAppearanceControls(document);
        decorateAvatars(document);
        decorateMessages();
        filterVisibleList();
        syncSettingsOverview();

        const contentObserver = new MutationObserver(function (mutations) {
            let chatContentChanged = false;
            let messagesChanged = false;
            let messageStructureChanged = false;
            let settingsChanged = false;

            mutations.forEach(function (mutation) {
                if (mutation.target === chatList || chatList.contains(mutation.target)) {
                    chatContentChanged = true;
                    captureRemovedChatState(mutation);
                }
                if (mutation.target === messagesList || messagesList.contains(mutation.target)) {
                    messagesChanged = true;
                    if (mutation.target === messagesList || mutationTouchesMessage(mutation)) {
                        messageStructureChanged = true;
                    }
                }
                if (settingsContentArea &&
                    (mutation.target === settingsContentArea || settingsContentArea.contains(mutation.target))) {
                    settingsChanged = true;
                }
            });

            if (chatContentChanged) {
                tagChatItems();
                enhanceInteractiveElements(chatList);
                decorateAvatars(chatList);
                filterVisibleList();
                restoreChatState();
            }
            if (messagesChanged) {
                if (messageStructureChanged) {
                    decorateMessages();
                    enhanceMessageActions(messagesList);
                }
                updateJumpToLatest();
            }
            if (settingsChanged) {
                enhanceInteractiveElements(settingsContentArea);
                enhancePasswordFields(settingsContentArea);
                enhanceAppearanceControls(settingsContentArea);
            }
        });

        contentObserver.observe(chatList, {childList: true, subtree: true});
        contentObserver.observe(messagesList, {childList: true, subtree: true});
        if (settingsContentArea) {
            contentObserver.observe(settingsContentArea, {childList: true, subtree: true});
        }

        const viewObserver = new MutationObserver(function () {
            const nextView = getCurrentView();
            if (nextView !== state.currentView) {
                if (nextView !== 'chats') {
                    state.chatSelectionEpoch += 1;
                }
                state.currentView = nextView;
                state.conversationFilter = 'all';
                searchInput.value = '';
                updateFilterButtons();
                updateSearchChrome();
            }
            enhanceInteractiveElements(settingsList);
            filterVisibleList();
            syncSettingsOverview();
        });

        viewObserver.observe(chatList, {attributes: true, attributeFilter: ['class']});
        viewObserver.observe(settingsList, {attributes: true, attributeFilter: ['class']});
        if (settingsContent) {
            viewObserver.observe(settingsContent, {attributes: true, attributeFilter: ['class']});
        }
        window.addEventListener('resize', syncSettingsOverview, {passive: true});

        const avatarObserver = new MutationObserver(function (mutations) {
            mutations.forEach(function (mutation) {
                mutation.addedNodes.forEach(function (node) {
                    if (node.nodeType === Node.ELEMENT_NODE) {
                        decorateAvatars(node);
                    }
                });
            });
        });
        avatarObserver.observe(document.body, {childList: true, subtree: true});

        tagChatItems();
        setupMessageLogAccessibility();
        setupBottomNavigationAccessibility();

        function getCurrentView() {
            const listIsVisible = !settingsList.classList.contains('d-none');
            const contentIsVisible = settingsContent && !settingsContent.classList.contains('d-none');
            return listIsVisible || contentIsVisible ? 'settings' : 'chats';
        }

        function syncSettingsOverview() {
            if (!settingsOverview) {
                return;
            }
            const listIsVisible = !settingsList.classList.contains('d-none');
            const contentIsVisible = settingsContent && !settingsContent.classList.contains('d-none');
            settingsOverview.hidden = window.innerWidth <= 768 || !listIsVisible || contentIsVisible;
        }

        function setupSurfaceCoordinator() {
            const legacyShowSettings = window.showSettings;
            const legacyShowSettingsSection = window.showSettingsSection;
            const legacyShowChatsTab = window.showChatsTab;
            const legacyShowExploreTab = window.showExploreTab;
            const legacyGoBackToChats = window.goBackToChats;
            const legacyBackToChats = window.backToChats;
            const legacySelectChat = window.selectChat;
            if (typeof legacyShowSettings !== 'function' || typeof legacyShowSettingsSection !== 'function' ||
                !mainContainer || !chatContent || !welcomeScreen) {
                return;
            }

            window.showSettings = function showCoordinatedSettings() {
                closeOpenDropdowns();
                if (typeof window.cleanupTransientChatUx === 'function') {
                    window.cleanupTransientChatUx();
                }
                if (!mainContainer.classList.contains('settings-mode')) {
                    settingsReturnSurface = getSettingsReturnSurface();
                    settingsEntryOpener = document.activeElement && document.activeElement !== document.body
                        ? document.activeElement
                        : null;
                }
                const result = withoutNavigationToast(function () {
                    return legacyShowSettings.apply(window, arguments);
                });
                enterSettingsRootSurface();
                if (window.innerWidth > 768) {
                    window.showSettingsSection(lastSettingsSection);
                    focusDesktopSettingsAfterEntry();
                } else {
                    ensureSettingsHistory('root');
                    focusSettingsRoot();
                }
                dismissNavigationToast();
                return result;
            };

            window.showSettingsSection = function showCoordinatedSettingsSection(section) {
                const requestedSection = settingsSections.includes(section) ? section : 'profile';
                if (!mainContainer.classList.contains('settings-mode')) {
                    settingsReturnSurface = getSettingsReturnSurface();
                    settingsEntryOpener = document.activeElement && document.activeElement !== document.body
                        ? document.activeElement
                        : null;
                    withoutNavigationToast(function () {
                        legacyShowSettings.call(window);
                    });
                    enterSettingsRootSurface();
                    ensureSettingsHistory('root');
                }
                lastSettingsSection = requestedSection;
                localStorage.setItem('hi.settings.section', requestedSection);
                const result = legacyShowSettingsSection.call(window, requestedSection);
                enterSettingsDetailSurface(requestedSection);
                ensureSettingsHistory('detail');
                dismissNavigationToast();
                return result;
            };

            window.closeSettings = function closeSettings(returnSurface) {
                const destination = returnSurface || settingsReturnSurface;
                closeOpenDropdowns();
                if (destination === 'list') {
                    leaveAppHistoryToList();
                } else {
                    leaveSettingsHistory();
                }
                mainContainer.classList.remove('settings-mode', 'settings-detail-mode');
                mainContainer.removeAttribute('data-app-surface');
                setSurfaceVisibility(settingsList, false);
                setSurfaceVisibility(settingsContent, false);
                if (settingsOverview) {
                    settingsOverview.hidden = true;
                }
                clearSettingsSelection();
                searchInput.value = '';
                searchInput.placeholder = 'Search conversations';

                if (window.innerWidth <= 768) {
                    setSurfaceVisibility(welcomeScreen, false);
                    if (destination === 'chat') {
                        setSurfaceVisibility(chatList, true);
                        setSurfaceVisibility(chatContent, true);
                        hideMobileSidebarSurface();
                        hideMobileBottomNavigation();
                    } else {
                        setSurfaceVisibility(chatContent, false);
                        setSurfaceVisibility(chatList, true);
                        showMobileSidebarSurface();
                        showMobileBottomNavigation();
                        activateBottomNavigation('chats');
                    }
                } else {
                    setSurfaceVisibility(chatList, true);
                    sidebar.classList.remove('show');
                    sidebar.inert = false;
                    sidebar.removeAttribute('aria-hidden');
                    if (destination === 'chat') {
                        setSurfaceVisibility(welcomeScreen, false);
                        setSurfaceVisibility(chatContent, true);
                    } else {
                        setSurfaceVisibility(chatContent, false);
                        setSurfaceVisibility(welcomeScreen, true);
                    }
                }

                updateFilterButtons();
                updateSearchChrome();
                filterVisibleList();
                if (destination === 'chat' && currentChatId &&
                    !messagesList.querySelector('.message') && typeof window.loadMessages === 'function') {
                    window.loadMessages(currentChatId);
                }
                syncCurrentStates();
                focusReturnedSurface(destination);
            };

            window.backToSettingsRoot = function backToSettingsRoot() {
                if (!mainContainer.classList.contains('settings-mode')) {
                    window.showSettings();
                    return;
                }
                if (window.innerWidth <= 768 && getSettingsHistorySurface() === 'detail') {
                    window.history.back();
                    return;
                }
                enterSettingsRootSurface();
                ensureSettingsHistory('root');
                focusSettingsRoot(true);
            };

            window.showMeTab = function showSettingsTab() {
                if (window.innerWidth <= 768 && mainContainer.classList.contains('settings-mode') &&
                    mainContainer.classList.contains('settings-detail-mode')) {
                    window.backToSettingsRoot();
                    activateBottomNavigation('settings');
                    return;
                }
                window.showSettings();
                activateBottomNavigation('settings');
            };

            window.showChatsTab = function showConversationListTab() {
                if (mainContainer.classList.contains('settings-mode')) {
                    window.closeSettings('list');
                    return;
                }
                if (currentChatId !== null || getAppHistorySurface() === 'chat') {
                    leaveAppHistoryToList();
                    leaveChatToList({focusList: true});
                    return;
                }
                const result = typeof legacyShowChatsTab === 'function'
                    ? legacyShowChatsTab.apply(window, arguments)
                    : undefined;
                if (window.innerWidth <= 768) {
                    showConversationListSurface();
                }
                return result;
            };

            window.showChatHome = function showChatHome() {
                closeOpenDropdowns();
                dismissNavigationToast();
                pendingHistoryChatId = '';
                leaveAppHistoryToList();
                leaveChatToList({
                    clearSearch: true,
                    clearFocusedChat: true,
                    focusList: false
                });
            };

            window.showExploreTab = function showCoordinatedNewConversation() {
                const returnToSettings = mainContainer.classList.contains('settings-mode');
                const returnToDetail = mainContainer.classList.contains('settings-detail-mode');
                const modal = document.getElementById('newChatModal');
                let continuingToConversation = false;

                if (modal) {
                    modal.addEventListener('hidden.bs.modal', function restoreSurfaceAfterNewConversation() {
                        continuingToConversation = modal.dataset.continueUserSelection === 'true';
                        window.setTimeout(function () {
                            if (continuingToConversation) {
                                return;
                            }
                            if (returnToSettings && mainContainer.classList.contains('settings-mode')) {
                                if (returnToDetail) {
                                    enterSettingsDetailSurface(lastSettingsSection);
                                } else {
                                    enterSettingsRootSurface();
                                }
                                activateBottomNavigation('settings');
                            } else if (chatContent.classList.contains('d-none')) {
                                activateBottomNavigation('chats');
                            }
                        }, 0);
                    }, {once: true});
                }

                activateBottomNavigation('new');
                if (typeof window.showNewChatModal === 'function') {
                    return window.showNewChatModal();
                }
                return typeof legacyShowExploreTab === 'function'
                    ? legacyShowExploreTab.apply(window, arguments)
                    : undefined;
            };

            if (typeof legacySelectChat === 'function') {
                window.selectChat = function selectCoordinatedChat() {
                    const hadSettingsHistory = Boolean(getSettingsHistorySurface());
                    const result = legacySelectChat.apply(window, arguments);
                    const selectedChatId = normalizeHistoryChatId(currentChatId);
                    if (!selectedChatId) {
                        return result;
                    }
                    closeOpenDropdowns();
                    leaveSettingsHistory();
                    mainContainer.classList.remove('settings-mode', 'settings-detail-mode');
                    mainContainer.removeAttribute('data-app-surface');
                    setSurfaceVisibility(settingsList, false);
                    setSurfaceVisibility(settingsContent, false);
                    setSurfaceVisibility(welcomeScreen, false);
                    setSurfaceVisibility(chatList, true);
                    setSurfaceVisibility(chatContent, true);
                    searchInput.placeholder = 'Search conversations';

                    if (window.innerWidth <= 768) {
                        hideMobileSidebarSurface();
                        hideMobileBottomNavigation();
                    } else {
                        sidebar.classList.remove('show');
                        sidebar.inert = false;
                        sidebar.removeAttribute('aria-hidden');
                    }
                    beginMessageLogLoad(currentChatInfo && currentChatInfo.title);
                    if (!appHistoryRestoring) {
                        if (hadSettingsHistory) {
                            pendingHistoryChatId = selectedChatId;
                        } else {
                            commitChatHistory(selectedChatId);
                        }
                    }
                    syncCurrentStates();
                    return result;
                };
            }

            if (typeof legacyGoBackToChats === 'function') {
                window.goBackToChats = function quietMobileChatBack() {
                    if (!appHistoryRestoring && getAppHistorySurface() === 'chat') {
                        window.history.back();
                        return undefined;
                    }
                    const result = leaveChatToList({focusList: true});
                    dismissNavigationToast();
                    return result;
                };
            }

            if (typeof legacyBackToChats === 'function') {
                window.backToChats = function quietLegacySettingsBack() {
                    const invocationArguments = arguments;
                    const result = withoutNavigationToast(function () {
                        return legacyBackToChats.apply(window, invocationArguments);
                    });
                    dismissNavigationToast();
                    return result;
                };
            }

            function normalizeSettingsAfterResize() {
                window.clearTimeout(settingsResizeTimer);
                settingsResizeTimer = window.setTimeout(function () {
                    if (!mainContainer.classList.contains('settings-mode')) {
                        return;
                    }
                    const focusedControl = settingsContent && settingsContent.contains(document.activeElement)
                        ? document.activeElement
                        : null;
                    const previousScrollTop = settingsContent ? settingsContent.scrollTop : 0;
                    if (window.innerWidth > 768 || mainContainer.classList.contains('settings-detail-mode')) {
                        enterSettingsDetailSurface(lastSettingsSection);
                        if (settingsContent) {
                            settingsContent.scrollTop = Math.min(
                                previousScrollTop,
                                Math.max(0, settingsContent.scrollHeight - settingsContent.clientHeight)
                            );
                        }
                        if (window.innerWidth <= 768) {
                            ensureSettingsHistory('detail');
                        }
                    } else {
                        enterSettingsRootSurface();
                        ensureSettingsHistory('root');
                    }
                    if (focusedControl && focusedControl.isConnected &&
                        settingsContent && settingsContent.contains(focusedControl)) {
                        window.requestAnimationFrame(function keepFocusedSettingVisible() {
                            focusedControl.scrollIntoView({block: 'nearest', inline: 'nearest'});
                        });
                    }
                }, 0);
            }

            window.addEventListener('resize', normalizeSettingsAfterResize, {passive: true});
            if (window.visualViewport) {
                window.visualViewport.addEventListener('resize', normalizeSettingsAfterResize, {passive: true});
            }

            window.addEventListener('popstate', function restoreApplicationHistory(event) {
                const visibleModal = document.querySelector('.modal.show') ||
                    (activeModalElement && activeModalElement.isConnected ? activeModalElement : null);
                if (!settingsModalHistorySyncing && !settingsHistorySyncing && visibleModal) {
                    settingsModalHistorySyncing = true;
                    window.history.forward();
                    const modalInstance = window.bootstrap && bootstrap.Modal.getOrCreateInstance(visibleModal);
                    if (modalInstance) {
                        if (activeModalElement === visibleModal && activeModalOpening) {
                            visibleModal.addEventListener('shown.bs.modal', function dismissModalAfterOpening() {
                                bootstrap.Modal.getOrCreateInstance(visibleModal).hide();
                            }, {once: true});
                        }
                        modalInstance.hide();
                        window.setTimeout(function retryModalDismissAfterTransition() {
                            if (visibleModal.classList.contains('show')) {
                                bootstrap.Modal.getOrCreateInstance(visibleModal).hide();
                            }
                        }, 360);
                    }
                    window.clearTimeout(settingsModalHistorySyncTimer);
                    settingsModalHistorySyncTimer = window.setTimeout(function () {
                        settingsModalHistorySyncing = false;
                    }, 800);
                    return;
                }
                if (settingsModalHistorySyncing) {
                    settingsModalHistorySyncing = false;
                    window.clearTimeout(settingsModalHistorySyncTimer);
                    return;
                }
                if (settingsHistorySyncing) {
                    settingsHistorySyncing = false;
                    window.clearTimeout(settingsHistorySyncTimer);
                    flushPendingChatHistory();
                    return;
                }

                const historyState = event.state || {};
                if (historyState.hiSettingsSession === settingsHistorySession) {
                    if (!mainContainer.classList.contains('settings-mode')) {
                        window.showSettings();
                    }
                    if (historyState.hiSettingsSurface === 'detail') {
                        window.showSettingsSection(historyState.hiSettingsSection || lastSettingsSection);
                    } else if (window.innerWidth > 768) {
                        window.showSettingsSection(historyState.hiSettingsSection || lastSettingsSection);
                        focusDesktopSettingsAfterEntry();
                    } else {
                        enterSettingsRootSurface();
                        focusSettingsRoot(true);
                    }
                    return;
                }

                const appSurface = getAppHistorySurface(historyState);
                if (appSurface === 'chat') {
                    if (mainContainer.classList.contains('settings-mode')) {
                        window.closeSettings('chat');
                    }
                    restoreChatFromHistory(historyState.hiChatId);
                    return;
                }

                if (appSurface === 'list') {
                    if (mainContainer.classList.contains('settings-mode')) {
                        window.closeSettings('list');
                    }
                    leaveChatToList({focusList: true});
                    return;
                }

                if (mainContainer.classList.contains('settings-mode')) {
                    window.closeSettings();
                }
            });

            initializeAppHistory();
        }

        function getSettingsReturnSurface() {
            if (!chatContent.classList.contains('d-none')) {
                return 'chat';
            }
            if (window.innerWidth <= 768 && sidebar.classList.contains('show') &&
                !chatList.classList.contains('d-none')) {
                return 'list';
            }
            return 'welcome';
        }

        function enterSettingsRootSurface() {
            mainContainer.classList.add('settings-mode');
            mainContainer.classList.remove('settings-detail-mode');
            mainContainer.setAttribute('data-app-surface', 'settings-root');
            setSurfaceVisibility(chatList, false);
            setSurfaceVisibility(chatContent, false);
            setSurfaceVisibility(welcomeScreen, false);
            setSurfaceVisibility(settingsContent, false);
            setSurfaceVisibility(settingsList, true);
            if (settingsOverview) {
                settingsOverview.hidden = true;
            }
            clearSettingsSelection();
            searchInput.value = '';
            searchInput.placeholder = 'Settings categories';
            updateSearchChrome();

            if (window.innerWidth <= 768) {
                showMobileSidebarSurface();
                showMobileBottomNavigation();
                activateBottomNavigation('settings');
            } else {
                sidebar.classList.remove('show');
                sidebar.inert = false;
                sidebar.removeAttribute('aria-hidden');
            }
            syncCurrentStates();
        }

        function enterSettingsDetailSurface(section) {
            mainContainer.classList.add('settings-mode', 'settings-detail-mode');
            mainContainer.setAttribute('data-app-surface', 'settings-detail');
            setSurfaceVisibility(chatList, false);
            setSurfaceVisibility(chatContent, false);
            setSurfaceVisibility(welcomeScreen, false);
            setSurfaceVisibility(settingsContent, true);
            if (settingsOverview) {
                settingsOverview.hidden = true;
            }
            setActiveSettingsSection(section);
            settingsContent.scrollTop = 0;

            if (window.innerWidth <= 768) {
                setSurfaceVisibility(settingsList, false);
                hideMobileSidebarSurface();
                showMobileBottomNavigation();
                activateBottomNavigation('settings');
            } else {
                setSurfaceVisibility(settingsList, true);
                sidebar.classList.remove('show');
                sidebar.inert = false;
                sidebar.removeAttribute('aria-hidden');
            }
            syncCurrentStates();
        }

        function showConversationListSurface() {
            mainContainer.classList.remove('settings-mode', 'settings-detail-mode');
            mainContainer.removeAttribute('data-app-surface');
            setSurfaceVisibility(settingsList, false);
            setSurfaceVisibility(settingsContent, false);
            setSurfaceVisibility(welcomeScreen, false);
            setSurfaceVisibility(chatContent, false);
            setSurfaceVisibility(chatList, true);
            showMobileSidebarSurface();
            showMobileBottomNavigation();
            activateBottomNavigation('chats');
            searchInput.placeholder = 'Search conversations';
            window.setTimeout(function () {
                searchInput.focus({preventScroll: true});
            }, 180);
        }

        function leaveChatToList(options) {
            const settings = Object.assign({
                clearSearch: false,
                clearFocusedChat: false,
                focusList: false
            }, options || {});
            const input = document.getElementById('messageInput');
            const previousChatKey = state.activeChatKey || state.focusedChatKey;
            const hadActiveChat = currentChatId !== null || Boolean(state.activeChatKey) ||
                !chatContent.classList.contains('d-none');

            if (input && state.activeChatKey) {
                const draftToSave = input.dataset.editMessageId ? draftBeforeEdit : input.value;
                saveChatDraft(state.activeChatKey, draftToSave);
            }
            if (typeof window.cleanupTransientChatUx === 'function') {
                window.cleanupTransientChatUx();
            }
            if (typingTimeout !== null) {
                window.clearTimeout(typingTimeout);
                typingTimeout = null;
            }
            if (currentChatId !== null && typeof markClientSendSemanticsChanged === 'function') {
                markClientSendSemanticsChanged();
            }

            currentChatId = null;
            currentChatInfo = null;
            selectedChatElement = null;
            state.activeChatKey = '';
            if (settings.clearFocusedChat) {
                state.focusedChatKey = '';
            } else if (previousChatKey) {
                state.focusedChatKey = previousChatKey;
            }
            if (hadActiveChat) {
                state.chatSelectionEpoch += 1;
            }
            state.currentView = 'chats';
            if (settings.clearSearch) {
                state.conversationFilter = 'all';
                searchInput.value = '';
            }

            mainContainer.classList.remove('settings-mode', 'settings-detail-mode', 'bottom-nav-hidden');
            mainContainer.removeAttribute('data-app-surface');
            setSurfaceVisibility(settingsList, false);
            setSurfaceVisibility(settingsContent, false);
            setSurfaceVisibility(chatList, true);
            setSurfaceVisibility(chatContent, false);
            setSurfaceVisibility(welcomeScreen, window.innerWidth > 768);
            if (settingsOverview) {
                settingsOverview.hidden = true;
            }
            clearSettingsSelection();
            chatList.querySelectorAll(':scope > .chat-item').forEach(function (item) {
                item.classList.remove('active');
                item.removeAttribute('aria-current');
                item.setAttribute('aria-selected', 'false');
            });

            searchInput.placeholder = 'Search conversations';
            updateFilterButtons();
            updateSearchChrome();
            filterVisibleList();
            if (window.innerWidth <= 768) {
                showMobileSidebarSurface();
                showMobileBottomNavigation();
            } else {
                sidebar.classList.remove('show');
                sidebar.inert = false;
                sidebar.removeAttribute('aria-hidden');
                if (sidebarOverlay) {
                    sidebarOverlay.classList.remove('show');
                }
                document.body.style.overflow = '';
            }
            activateBottomNavigation('chats');
            messagesList.setAttribute('aria-busy', 'false');
            messagesList.setAttribute('aria-live', 'off');
            syncSettingsOverview();
            syncCurrentStates();
            refreshConversationRowStates();

            if (settings.focusList) {
                focusConversationRow(previousChatKey);
            }
            return undefined;
        }

        function restoreChatFromHistory(chatId) {
            const normalizedChatId = normalizeHistoryChatId(chatId);
            if (!normalizedChatId) {
                normalizeMissingHistoryChat();
                return;
            }
            if (normalizeHistoryChatId(currentChatId) === normalizedChatId &&
                !chatContent.classList.contains('d-none')) {
                pendingHistoryRestoreChatId = '';
                return;
            }

            const item = chatList.querySelector(':scope > .chat-item[data-chat-id="' + normalizedChatId + '"]');
            if (!item || !item.__pmChatData) {
                pendingHistoryRestoreChatId = normalizedChatId;
                setSurfaceVisibility(chatContent, false);
                setSurfaceVisibility(welcomeScreen, false);
                setSurfaceVisibility(chatList, true);
                if (window.innerWidth <= 768) {
                    showMobileSidebarSurface();
                    showMobileBottomNavigation();
                }
                schedulePendingHistoryChatRestore();
                return;
            }

            pendingHistoryRestoreChatId = '';
            window.clearTimeout(pendingHistoryChatTimer);
            appHistoryRestoring = true;
            try {
                item.click();
            } finally {
                appHistoryRestoring = false;
            }
            if (normalizeHistoryChatId(currentChatId) !== normalizedChatId) {
                pendingHistoryRestoreChatId = normalizedChatId;
                schedulePendingHistoryChatRestore();
            }
        }

        function schedulePendingHistoryChatRestore() {
            window.clearTimeout(pendingHistoryChatTimer);
            pendingHistoryChatTimer = window.setTimeout(function retryHistoryChatRestore() {
                if (!pendingHistoryRestoreChatId || getAppHistorySurface() !== 'chat') {
                    return;
                }
                const chatId = pendingHistoryRestoreChatId;
                const item = chatList.querySelector(':scope > .chat-item[data-chat-id="' + chatId + '"]');
                if (item && item.__pmChatData) {
                    restoreChatFromHistory(chatId);
                    return;
                }
                normalizeMissingHistoryChat();
            }, 5000);
        }

        function restorePendingHistoryChat() {
            if (pendingHistoryRestoreChatId && getAppHistorySurface() === 'chat') {
                restoreChatFromHistory(pendingHistoryRestoreChatId);
            }
        }

        function normalizeMissingHistoryChat() {
            pendingHistoryRestoreChatId = '';
            window.clearTimeout(pendingHistoryChatTimer);
            const currentState = Object.assign({}, window.history.state || {});
            clearSettingsHistoryFields(currentState);
            delete currentState.hiChatId;
            window.history.replaceState(Object.assign(currentState, {
                hiAppSession: appHistorySession,
                hiAppSurface: 'list'
            }), '');
            leaveChatToList({focusList: true});
            if (typeof window.showToast === 'function') {
                window.showToast('This conversation is no longer available', 'info', 3000);
            }
        }

        function focusConversationRow(chatKey) {
            window.setTimeout(function () {
                const items = getVisibleChatItems();
                const target = (chatKey && items.find(function (item) {
                    return getChatKey(item) === chatKey;
                })) || items[0] || searchInput;
                if (target && !target.closest('[inert]')) {
                    target.focus({preventScroll: true});
                    if (target.classList && target.classList.contains('chat-item')) {
                        target.scrollIntoView({block: 'nearest', inline: 'nearest'});
                    }
                }
            }, 80);
        }

        function setSurfaceVisibility(element, visible) {
            if (!element) {
                return;
            }
            element.classList.toggle('d-none', !visible);
            element.inert = !visible;
            if (visible) {
                element.removeAttribute('aria-hidden');
            } else {
                element.setAttribute('aria-hidden', 'true');
            }
        }

        function showMobileSidebarSurface() {
            sidebar.classList.add('show');
            sidebar.inert = false;
            sidebar.removeAttribute('aria-hidden');
            if (sidebarOverlay) {
                sidebarOverlay.classList.remove('show');
            }
            document.body.style.overflow = '';
        }

        function hideMobileSidebarSurface() {
            sidebar.classList.remove('show');
            sidebar.inert = true;
            sidebar.setAttribute('aria-hidden', 'true');
            if (sidebarOverlay) {
                sidebarOverlay.classList.remove('show');
            }
            document.body.style.overflow = '';
        }

        function showMobileBottomNavigation() {
            if (window.innerWidth > 768 || !mobileBottomNav) {
                return;
            }
            mobileBottomNav.classList.remove('hidden');
            mobileBottomNav.inert = false;
            mobileBottomNav.removeAttribute('aria-hidden');
            mainContainer.classList.remove('bottom-nav-hidden');
        }

        function hideMobileBottomNavigation() {
            if (window.innerWidth > 768 || !mobileBottomNav) {
                return;
            }
            mobileBottomNav.classList.add('hidden');
            mobileBottomNav.inert = true;
            mobileBottomNav.setAttribute('aria-hidden', 'true');
            mainContainer.classList.add('bottom-nav-hidden');
        }

        function activateBottomNavigation(surface) {
            if (!mobileBottomNav) {
                return;
            }
            const items = Array.from(mobileBottomNav.querySelectorAll('.bottom-nav-item'));
            const activeIndex = surface === 'settings' ? 2 : surface === 'new' ? 1 : 0;
            items.forEach(function (item, index) {
                item.classList.toggle('active', index === activeIndex);
                item.setAttribute('aria-pressed', String(index === activeIndex));
                if (index === activeIndex && surface !== 'new') {
                    item.setAttribute('aria-current', 'page');
                } else {
                    item.removeAttribute('aria-current');
                }
            });
        }

        function setupBottomNavigationAccessibility() {
            if (!mobileBottomNav) {
                return;
            }
            if (mobileBottomNav.tagName !== 'NAV') {
                mobileBottomNav.setAttribute('role', 'navigation');
            }
            if (!mobileBottomNav.hasAttribute('aria-label')) {
                mobileBottomNav.setAttribute('aria-label', 'Primary');
            }
            const items = Array.from(mobileBottomNav.querySelectorAll('.bottom-nav-item'));
            if (items[0] && !items[0].hasAttribute('aria-controls')) {
                items[0].setAttribute('aria-controls', 'sidebar');
            }
            if (items[1]) {
                items[1].setAttribute('aria-haspopup', 'dialog');
                if (!items[1].hasAttribute('aria-controls')) {
                    items[1].setAttribute('aria-controls', 'newChatModal');
                }
            }
            if (items[2] && !items[2].hasAttribute('aria-controls')) {
                items[2].setAttribute('aria-controls', 'settingsList settingsContent');
            }
            syncBottomNavigationAccess();
            window.addEventListener('resize', syncBottomNavigationAccess, {passive: true});
        }

        function syncBottomNavigationAccess() {
            if (!mobileBottomNav) {
                return;
            }
            const hidden = window.innerWidth > 768 || mobileBottomNav.classList.contains('hidden');
            mobileBottomNav.inert = hidden;
            if (hidden) {
                mobileBottomNav.setAttribute('aria-hidden', 'true');
            } else {
                mobileBottomNav.removeAttribute('aria-hidden');
            }
        }

        function setActiveSettingsSection(section) {
            Array.from(settingsList.querySelectorAll(':scope > .settings-item')).forEach(function (item) {
                const isActive = item.dataset.pmSection === section;
                item.classList.toggle('active', isActive);
                if (isActive) {
                    item.setAttribute('aria-current', 'page');
                    lastSettingsOpener = item;
                } else {
                    item.removeAttribute('aria-current');
                }
            });
        }

        function clearSettingsSelection() {
            settingsList.querySelectorAll(':scope > .settings-item').forEach(function (item) {
                item.classList.remove('active');
                item.removeAttribute('aria-current');
            });
        }

        function focusSettingsRoot(preferLastOpener) {
            window.setTimeout(function () {
                const target = preferLastOpener && lastSettingsOpener && lastSettingsOpener.isConnected
                    ? lastSettingsOpener
                    : document.getElementById('settingsListTitle') ||
                    settingsList.querySelector(':scope > .settings-item');
                if (target && !settingsList.classList.contains('d-none') && !settingsList.closest('[inert]')) {
                    target.focus({preventScroll: true});
                }
            }, 180);
        }

        function focusDesktopSettingsAfterEntry() {
            window.setTimeout(function () {
                if (window.innerWidth <= 768 || !mainContainer.classList.contains('settings-detail-mode')) {
                    return;
                }
                const activeElement = document.activeElement;
                const activeIsVisible = activeElement && activeElement !== document.body &&
                    activeElement.getClientRects().length > 0 && !activeElement.closest('[inert]');
                if (!activeIsVisible && lastSettingsOpener && lastSettingsOpener.isConnected) {
                    lastSettingsOpener.focus({preventScroll: true});
                }
            }, 180);
        }

        function setupReliableDropdowns() {
            document.querySelectorAll('[data-pm-dropdown]').forEach(function (toggle) {
                const menu = toggle.closest('.dropdown') && toggle.closest('.dropdown').querySelector('.dropdown-menu');
                toggle.dataset.dropdownEnhanced = 'true';
                toggle.setAttribute('aria-haspopup', 'menu');
                if (menu) {
                    menu.setAttribute('role', 'menu');
                    menu.querySelectorAll('.dropdown-item').forEach(function (item) {
                        item.setAttribute('role', 'menuitem');
                    });
                }
                toggle.addEventListener('keydown', function openDropdownFromKeyboard(event) {
                    if (event.key === 'Escape' && menu && menu.classList.contains('show')) {
                        event.preventDefault();
                        event.stopPropagation();
                        bootstrap.Dropdown.getOrCreateInstance(toggle).hide();
                        return;
                    }
                    if (!['ArrowDown', 'Enter', ' ', 'Spacebar'].includes(event.key) || !menu ||
                        !window.bootstrap || !bootstrap.Dropdown) {
                        return;
                    }
                    event.preventDefault();
                    event.stopPropagation();
                    bootstrap.Dropdown.getOrCreateInstance(toggle).show();
                    const firstItem = menu.querySelector('.dropdown-item:not(.disabled)');
                    if (firstItem) {
                        firstItem.focus({preventScroll: true});
                    }
                });
            });
            window.addEventListener('keydown', function navigateCustomDropdownBeforeBootstrap(event) {
                const menu = event.target.closest && event.target.closest('.dropdown-menu.show');
                const toggle = menu && menu.closest('.dropdown') &&
                    menu.closest('.dropdown').querySelector('[data-pm-dropdown]');
                const handledKeys = ['ArrowDown', 'ArrowUp', 'Home', 'End', 'Escape'];
                if (!menu || !toggle || !handledKeys.includes(event.key)) {
                    return;
                }
                event.preventDefault();
                event.stopImmediatePropagation();
                if (event.key === 'Escape') {
                    if (window.bootstrap && bootstrap.Dropdown) {
                        bootstrap.Dropdown.getOrCreateInstance(toggle).hide();
                    }
                    toggle.focus({preventScroll: true});
                    return;
                }
                const items = Array.from(menu.querySelectorAll('.dropdown-item:not(.disabled)'));
                if (!items.length) {
                    return;
                }
                const currentIndex = items.indexOf(document.activeElement);
                const nextIndex = event.key === 'Home' ? 0 : event.key === 'End' ? items.length - 1 :
                    event.key === 'ArrowDown' ? (currentIndex + 1 + items.length) % items.length :
                        (currentIndex - 1 + items.length) % items.length;
                items[nextIndex].focus({preventScroll: true});
            }, true);
            document.addEventListener('click', function openEnhancedDropdown(event) {
                const toggle = event.target.closest && event.target.closest('[data-pm-dropdown]');
                if (!toggle || !window.bootstrap || !bootstrap.Dropdown) {
                    return;
                }
                event.stopPropagation();
                closeOpenDropdowns(toggle);
                bootstrap.Dropdown.getOrCreateInstance(toggle).toggle();
            }, true);
            document.addEventListener('click', function keepDropdownActionsInApp(event) {
                const action = event.target.closest && event.target.closest('a.dropdown-item[href="#"]');
                if (action) {
                    event.preventDefault();
                }
            }, true);
            document.addEventListener('click', function dismissCompletedDropdown(event) {
                const menuAction = event.target.closest && event.target.closest('.dropdown-item');
                const openMenu = event.target.closest && event.target.closest('.dropdown-menu.show');
                const owningToggle = menuAction && menuAction.closest('.dropdown') &&
                    menuAction.closest('.dropdown').querySelector('[data-pm-dropdown]');
                const restoreKeyboardFocus = Boolean(menuAction && event.detail === 0);
                if (menuAction || !openMenu) {
                    closeOpenDropdowns();
                }
                if (restoreKeyboardFocus && owningToggle) {
                    window.setTimeout(function restoreDropdownTriggerAfterAction() {
                        const modalIsOpen = Boolean(document.querySelector('.modal.show'));
                        const toggleIsVisible = owningToggle.isConnected && owningToggle.getClientRects().length > 0 &&
                            !owningToggle.closest('[inert]');
                        if (!modalIsOpen && toggleIsVisible &&
                            (!document.activeElement || document.activeElement === document.body ||
                                document.activeElement.getClientRects().length === 0)) {
                            owningToggle.focus({preventScroll: true});
                        }
                    }, 0);
                }
            });
        }

        function closeOpenDropdowns(exceptToggle) {
            document.querySelectorAll('[data-pm-dropdown]').forEach(function (toggle) {
                if (toggle === exceptToggle) {
                    return;
                }
                const menu = toggle.closest('.dropdown') && toggle.closest('.dropdown').querySelector('.dropdown-menu');
                const instance = window.bootstrap && bootstrap.Dropdown.getInstance(toggle);
                if (instance && menu && menu.classList.contains('show')) {
                    instance.hide();
                }
                toggle.setAttribute('aria-expanded', 'false');
                if (menu) {
                    menu.classList.remove('show');
                }
            });
        }

        function getSettingsHistorySurface() {
            const historyState = window.history.state || {};
            return historyState.hiSettingsSession === settingsHistorySession
                ? historyState.hiSettingsSurface || ''
                : '';
        }

        function ensureSettingsHistory(surface) {
            if (window.innerWidth > 768 || settingsHistorySyncing) {
                return;
            }
            const currentSurface = getSettingsHistorySurface();
            const currentState = Object.assign({}, window.history.state || {});
            if (!currentSurface) {
                const returnAppSurface = getAppHistorySurface(currentState) === 'chat' ? 'chat' : 'list';
                const rootState = Object.assign({}, currentState, {
                    hiSettingsSession: settingsHistorySession,
                    hiSettingsSurface: 'root',
                    hiSettingsSection: lastSettingsSection,
                    hiAppSession: appHistorySession,
                    hiAppSurface: 'settings-root',
                    hiAppReturnSurface: returnAppSurface,
                    hiAppSettingsDepth: 1
                });
                window.history.pushState(rootState, '');
                if (surface === 'detail') {
                    window.history.pushState(Object.assign({}, rootState, {
                        hiSettingsSurface: 'detail',
                        hiSettingsSection: lastSettingsSection,
                        hiAppSurface: 'settings-detail',
                        hiAppSettingsDepth: 2
                    }), '');
                }
                return;
            }
            if (surface === 'detail' && currentSurface === 'root') {
                window.history.pushState(Object.assign({}, currentState, {
                    hiSettingsSurface: 'detail',
                    hiSettingsSection: lastSettingsSection,
                    hiAppSession: appHistorySession,
                    hiAppSurface: 'settings-detail',
                    hiAppSettingsDepth: 2
                }), '');
                return;
            }
            window.history.replaceState(Object.assign({}, currentState, {
                hiSettingsSurface: surface,
                hiSettingsSection: lastSettingsSection,
                hiAppSession: appHistorySession,
                hiAppSurface: surface === 'detail' ? 'settings-detail' : 'settings-root',
                hiAppSettingsDepth: surface === 'detail' ? 2 : 1
            }), '');
        }

        function leaveSettingsHistory() {
            const surface = getSettingsHistorySurface();
            if (!surface || settingsHistorySyncing) {
                return;
            }
            settingsHistorySyncing = true;
            window.history.go(surface === 'detail' ? -2 : -1);
            window.clearTimeout(settingsHistorySyncTimer);
            settingsHistorySyncTimer = window.setTimeout(function () {
                settingsHistorySyncing = false;
            }, 800);
        }

        function initializeAppHistory() {
            const currentState = Object.assign({}, window.history.state || {});
            clearSettingsHistoryFields(currentState);
            delete currentState.hiChatId;
            window.history.replaceState(Object.assign(currentState, {
                hiAppSession: appHistorySession,
                hiAppSurface: 'list'
            }), '');
        }

        function getAppHistorySurface(historyState) {
            const stateValue = historyState || window.history.state || {};
            return stateValue.hiAppSession === appHistorySession
                ? String(stateValue.hiAppSurface || '')
                : '';
        }

        function normalizeHistoryChatId(value) {
            const normalized = String(value === undefined || value === null ? '' : value);
            return /^[1-9][0-9]*$/.test(normalized) && Number.isSafeInteger(Number(normalized))
                ? normalized
                : '';
        }

        function clearSettingsHistoryFields(historyState) {
            delete historyState.hiSettingsSession;
            delete historyState.hiSettingsSurface;
            delete historyState.hiSettingsSection;
            delete historyState.hiAppReturnSurface;
            delete historyState.hiAppSettingsDepth;
        }

        function commitChatHistory(chatId) {
            const normalizedChatId = normalizeHistoryChatId(chatId);
            if (!normalizedChatId || appHistoryRestoring) {
                return;
            }
            if (getSettingsHistorySurface()) {
                pendingHistoryChatId = normalizedChatId;
                return;
            }

            const currentState = Object.assign({}, window.history.state || {});
            const currentSurface = getAppHistorySurface(currentState);
            clearSettingsHistoryFields(currentState);
            const nextState = Object.assign(currentState, {
                hiAppSession: appHistorySession,
                hiAppSurface: 'chat',
                hiChatId: normalizedChatId
            });
            if (currentSurface === 'chat') {
                window.history.replaceState(nextState, '');
            } else {
                window.history.pushState(nextState, '');
            }
            pendingHistoryChatId = '';
        }

        function flushPendingChatHistory() {
            if (!pendingHistoryChatId) {
                return;
            }
            const chatId = pendingHistoryChatId;
            pendingHistoryChatId = '';
            window.queueMicrotask(function () {
                if (normalizeHistoryChatId(currentChatId) === chatId &&
                    !mainContainer.classList.contains('settings-mode')) {
                    commitChatHistory(chatId);
                }
            });
        }

        function leaveAppHistoryToList() {
            pendingHistoryChatId = '';
            const historyState = window.history.state || {};
            const surface = getAppHistorySurface(historyState);
            let distance = 0;
            if (surface === 'chat') {
                distance = 1;
            } else if (surface === 'settings-root' || surface === 'settings-detail') {
                distance = Number(historyState.hiAppSettingsDepth) || (surface === 'settings-detail' ? 2 : 1);
                if (historyState.hiAppReturnSurface === 'chat') {
                    distance += 1;
                }
            }
            if (!distance) {
                return;
            }
            if (surface === 'settings-root' || surface === 'settings-detail') {
                settingsHistorySyncing = true;
                window.clearTimeout(settingsHistorySyncTimer);
                settingsHistorySyncTimer = window.setTimeout(function () {
                    settingsHistorySyncing = false;
                }, 800);
            }
            window.history.go(-distance);
        }

        function focusReturnedSurface(destination) {
            window.setTimeout(function () {
                if (destination === 'chat') {
                    const target = window.innerWidth <= 768
                        ? document.querySelector('.mobile-chat-back button')
                        : document.getElementById('messageInput');
                    if (target) {
                        target.focus({preventScroll: true});
                    }
                    return;
                }
                if (destination === 'list') {
                    searchInput.focus({preventScroll: true});
                    return;
                }
                if (settingsEntryOpener && settingsEntryOpener.isConnected &&
                    settingsEntryOpener.getClientRects().length > 0 && !settingsEntryOpener.closest('[inert]')) {
                    settingsEntryOpener.focus({preventScroll: true});
                } else {
                    searchInput.focus({preventScroll: true});
                }
            }, 180);
        }

        function withoutNavigationToast(callback) {
            const legacyShowToast = window.showToast;
            if (typeof legacyShowToast !== 'function') {
                return callback();
            }
            window.showToast = function suppressNavigationToast(message) {
                if (/Settings opened|Back to settings|Back to chats/i.test(String(message))) {
                    return undefined;
                }
                return legacyShowToast.apply(window, arguments);
            };
            try {
                return callback();
            } finally {
                window.showToast = legacyShowToast;
            }
        }

        function dismissNavigationToast() {
            window.setTimeout(function () {
                const toast = document.getElementById('mainToast');
                const message = toast && toast.querySelector('.toast-body');
                if (!toast || !message || !/Settings opened|Back to settings|Back to chats/i.test(message.textContent)) {
                    return;
                }
                const instance = window.bootstrap && bootstrap.Toast.getInstance(toast);
                const clearMessage = function () {
                    if (/Settings opened|Back to settings|Back to chats/i.test(message.textContent)) {
                        message.textContent = '';
                    }
                };
                if (instance) {
                    toast.addEventListener('hidden.bs.toast', clearMessage, {once: true});
                    instance.hide();
                }
                window.setTimeout(clearMessage, 240);
            }, 0);
        }

        function setupChatIdentityTagging() {
            const legacyRenderChats = window.renderChats;
            if (typeof legacyRenderChats !== 'function') {
                return;
            }

            window.renderChats = function renderChatsWithStableIdentity(chats) {
                const result = legacyRenderChats.apply(this, arguments);
                // The hardened renderer validates, deduplicates, and assigns
                // authoritative IDs while reconciling rows. Index-based
                // retagging here would corrupt identity whenever input rows
                // are invalid or duplicated.
                tagChatItems();
                refreshConversationRowStates();
                restorePendingHistoryChat();
                return result;
            };
        }

        function setupRequestScoping() {
            const originalFetch = window.fetch.bind(window);
            const originalClearReply = typeof window.clearReply === 'function' ? window.clearReply : null;
            const originalClearAttachment = typeof window.clearAttachment === 'function'
                ? window.clearAttachment
                : null;
            let messageRequestSerial = 0;
            let scheduledReloadEpoch = -1;
            let scheduledReloadTimer = 0;

            window.fetch = function scopedFetch(input, init) {
                const request = getChatRequest(input, init);
                const chatKeyAtRequest = state.activeChatKey;
                const chatEpochAtRequest = state.chatSelectionEpoch;
                if (request && request.action === 'get_messages') {
                    messageRequestSerial += 1;
                }

                return originalFetch(input, init).then(function (response) {
                    if (!request) {
                        return response;
                    }

                    if (request.action === 'send_message' || request.action === 'upload_file') {
                        return response.clone().json().then(function (result) {
                            lastSendSucceeded = Boolean(result.success);
                            return response;
                        }).catch(function () {
                            lastSendSucceeded = false;
                            return response;
                        });
                    }

                    const isMessageRead = request.action === 'get_messages' ||
                        request.action === 'get_new_messages';
                    const isStale = isMessageRead && (!chatKeyAtRequest || !state.activeChatKey ||
                        chatEpochAtRequest !== state.chatSelectionEpoch || chatKeyAtRequest !== state.activeChatKey);
                    if (!isStale) {
                        return response;
                    }

                    const shouldRetryCurrentChat = request.action === 'get_messages' &&
                        Number(request.limit) === 30 && !request.before_message_id;
                    if (shouldRetryCurrentChat) {
                        scheduleSelectedChatReload(state.chatSelectionEpoch, state.activeChatKey, 0);
                    }
                    return createJsonResponse({success: false, messages: [], stale: true}, response);
                });
            };

            document.addEventListener('click', function (event) {
                const item = event.target.closest && event.target.closest('.chat-item');
                if (!item || item.parentElement !== chatList) {
                    return;
                }
                if (item.dataset.suppressNextClick === 'true' ||
                    (event.target.closest && event.target.closest('#chatRowMenu'))) {
                    return;
                }

                const sendButton = document.querySelector('.send-btn');
                if (sendButton && sendButton.disabled) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    if (typeof window.showToast === 'function') {
                        window.showToast('Wait for the current message to finish sending', 'info', 2600);
                    }
                    return;
                }

                const nextKey = getChatKey(item);
                const isNewSelection = nextKey && (!item.classList.contains('active') || selectedChatElement !== item);
                if (isNewSelection) {
                    const input = document.getElementById('messageInput');
                    if (input && state.activeChatKey) {
                        const draftToSave = input.dataset.editMessageId ? draftBeforeEdit : input.value;
                        saveChatDraft(state.activeChatKey, draftToSave);
                    }
                    selectedChatElement = item;
                    state.chatSelectionEpoch += 1;
                    state.activeChatKey = nextKey;
                    messagesList.innerHTML = '';
                    const loading = document.getElementById('loadingIndicator');
                    if (loading) {
                        loading.classList.add('show');
                    }
                    if (originalClearAttachment) {
                        originalClearAttachment();
                    }
                    if (originalClearReply) {
                        originalClearReply();
                    }
                    draftBeforeEdit = '';
                    if (input) {
                        input.value = chatDrafts.get(nextKey) || '';
                        input.placeholder = 'Type a message...';
                        input.style.height = 'auto';
                        delete input.dataset.replyTo;
                        delete input.dataset.editMessageId;
                    }
                }
            }, true);

            function reloadSelectedChat() {
                const selected = selectedChatElement && selectedChatElement.isConnected
                    ? selectedChatElement
                    : chatList.querySelector(':scope > .chat-item.active') ||
                        Array.from(chatList.querySelectorAll(':scope > .chat-item')).find(function (item) {
                            return getChatKey(item) === state.activeChatKey;
                        });
                if (selected && selected.isConnected) {
                    selectedChatElement = selected;
                    selected.click();
                }
            }

            function scheduleSelectedChatReload(expectedEpoch, expectedChatKey, attempt) {
                if (!canReloadSelectedChat(expectedEpoch, expectedChatKey)) {
                    return;
                }
                if (scheduledReloadEpoch !== expectedEpoch) {
                    window.clearTimeout(scheduledReloadTimer);
                    scheduledReloadEpoch = expectedEpoch;
                    scheduledReloadTimer = 0;
                } else if (scheduledReloadTimer) {
                    return;
                }

                const delay = Math.min(80 + attempt * 80, 1000);
                scheduledReloadTimer = window.setTimeout(function () {
                    scheduledReloadTimer = 0;
                    if (!canReloadSelectedChat(expectedEpoch, expectedChatKey)) {
                        scheduledReloadEpoch = -1;
                        return;
                    }
                    const sendButton = document.querySelector('.send-btn');
                    if (sendButton && sendButton.disabled) {
                        if (attempt < 60) {
                            scheduleSelectedChatReload(expectedEpoch, expectedChatKey, attempt + 1);
                        } else {
                            scheduledReloadEpoch = -1;
                        }
                        return;
                    }
                    const serialBeforeClick = messageRequestSerial;
                    reloadSelectedChat();
                    if (messageRequestSerial === serialBeforeClick && attempt < 60) {
                        scheduleSelectedChatReload(expectedEpoch, expectedChatKey, attempt + 1);
                    } else {
                        scheduledReloadEpoch = -1;
                    }
                }, delay);
            }

            function canReloadSelectedChat(expectedEpoch, expectedChatKey) {
                const chatContent = document.getElementById('chatContent');
                return Boolean(expectedChatKey) && expectedEpoch === state.chatSelectionEpoch &&
                    expectedChatKey === state.activeChatKey && state.currentView === 'chats' &&
                    chatContent && !chatContent.classList.contains('d-none');
            }
        }

        function getChatRequest(input, init) {
            const url = typeof input === 'string' ? input : input && input.url;
            if (!url || !url.includes('api/chat.php')) {
                return null;
            }
            const body = init && init.body;
            if (typeof body === 'string') {
                try {
                    return JSON.parse(body);
                } catch (error) {
                    return null;
                }
            }
            if (typeof FormData !== 'undefined' && body instanceof FormData) {
                return {
                    action: body.get('action'),
                    chat_id: body.get('chat_id')
                };
            }
            return null;
        }

        function createJsonResponse(payload, source) {
            return new Response(JSON.stringify(payload), {
                status: source.ok ? 200 : source.status,
                statusText: source.statusText,
                headers: {'Content-Type': 'application/json'}
            });
        }

        function setupComposerSafety() {
            const input = document.getElementById('messageInput');
            const sendButton = document.querySelector('.send-btn');
            if (!input || !sendButton) {
                return;
            }

            const legacyClearAttachment = typeof window.clearAttachment === 'function'
                ? window.clearAttachment
                : null;
            if (legacyClearAttachment) {
                window.clearAttachment = function preserveDraftWhenRemovingAttachment() {
                    const draft = input.value;
                    const sending = sendButton.disabled;
                    legacyClearAttachment();
                    if (!sending && draft) {
                        input.value = draft;
                        input.placeholder = 'Type a message...';
                        input.focus({preventScroll: true});
                    }
                };
            }

            sendButton.addEventListener('click', function (event) {
                if (sendButton.disabled || editInFlight) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    return;
                }
                if (input.dataset.editMessageId) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    submitMessageEdit();
                    return;
                }
                beginSendSnapshot();
            }, true);

            input.addEventListener('keypress', function (event) {
                if (event.key !== 'Enter' || event.shiftKey) {
                    return;
                }
                if (sendButton.disabled || editInFlight) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    return;
                }
                if (input.dataset.editMessageId) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    submitMessageEdit();
                    return;
                }
                beginSendSnapshot();
            }, true);

            input.addEventListener('keydown', function (event) {
                if (event.key === 'Escape' && input.dataset.editMessageId) {
                    event.preventDefault();
                    if (editInFlight) {
                        return;
                    }
                    delete input.dataset.editMessageId;
                    input.value = draftBeforeEdit;
                    draftBeforeEdit = '';
                    input.placeholder = 'Type a message...';
                    input.dispatchEvent(new Event('input', {bubbles: true}));
                    saveChatDraft(state.activeChatKey, input.value);
                }
            });

            input.addEventListener('input', function () {
                if (!input.dataset.editMessageId) {
                    saveChatDraft(state.activeChatKey, input.value);
                }
                if (sendButton.disabled) {
                    queuedDraft = input.value;
                }
            });

            document.addEventListener('click', function (event) {
                const editOption = event.target.closest && event.target.closest('#editOption');
                if (editOption && !sendButton.disabled) {
                    draftBeforeEdit = input.dataset.editMessageId ? draftBeforeEdit : input.value;
                    if (typeof window.clearReply === 'function') {
                        window.clearReply();
                    }
                    if (typeof window.clearAttachment === 'function') {
                        window.clearAttachment();
                    }
                }

                const lockedAction = event.target.closest && event.target.closest(
                    '.composer-action, #attachmentPreview button, .attachment-option, .context-menu-item'
                );
                if (sendButton.disabled && lockedAction) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                }
            }, true);

            messagesList.addEventListener('contextmenu', function (event) {
                if (sendButton.disabled) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                }
            }, true);

            messagesContainer.addEventListener('drop', function (event) {
                if (sendButton.disabled) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                }
            }, true);

            const sendObserver = new MutationObserver(function () {
                syncComposerLock();
                if (sendButton.disabled || (!sentDraft && !queuedDraft)) {
                    return;
                }
                const completedChatKey = sendChatKey || state.activeChatKey;
                const draftToRestore = queuedDraft || (!lastSendSucceeded ? sentDraft : '');
                if (state.activeChatKey === completedChatKey && !input.value && draftToRestore) {
                    input.value = draftToRestore;
                    input.dispatchEvent(new Event('input', {bubbles: true}));
                }
                saveChatDraft(completedChatKey, draftToRestore);
                sentDraft = '';
                queuedDraft = '';
                sendChatKey = '';
                lastSendSucceeded = null;
                refreshConversationRowStates();
            });
            sendObserver.observe(sendButton, {attributes: true, attributeFilter: ['disabled']});
            syncComposerLock();

            function beginSendSnapshot() {
                sentDraft = input.value;
                queuedDraft = '';
                sendChatKey = state.activeChatKey;
                lastSendSucceeded = null;
                refreshConversationRowStates();
                window.queueMicrotask(function () {
                    if (sendButton.disabled && input.value === sentDraft) {
                        input.value = '';
                    }
                });
            }

            function submitMessageEdit() {
                if (editInFlight || sendButton.disabled) {
                    return;
                }
                const messageId = input.dataset.editMessageId;
                const content = input.value.trim();
                const message = document.querySelector('[data-message-id="' + CSS.escape(messageId) + '"]');
                sentDraft = '';
                queuedDraft = '';
                lastSendSucceeded = null;
                if (!content) {
                    if (typeof window.showToast === 'function') {
                        window.showToast('An edited message cannot be empty', 'warning');
                    }
                    return;
                }
                if (message && message.dataset.messageType !== 'text') {
                    delete input.dataset.editMessageId;
                    input.value = draftBeforeEdit;
                    draftBeforeEdit = '';
                    input.placeholder = 'Type a message...';
                    input.dispatchEvent(new Event('input', {bubbles: true}));
                    saveChatDraft(state.activeChatKey, input.value);
                    if (typeof window.showToast === 'function') {
                        window.showToast('Attachment messages cannot be edited here', 'warning');
                    }
                    return;
                }

                const originalButtonChildren = Array.from(sendButton.childNodes, function (node) {
                    return node.cloneNode(true);
                });
                const requestId = ++editRequestId;
                editInFlight = true;
                sendButton.disabled = true;
                const spinner = document.createElement('i');
                spinner.className = 'fas fa-spinner fa-spin';
                spinner.setAttribute('aria-hidden', 'true');
                sendButton.replaceChildren(spinner);
                const editController = typeof AbortController === 'function' ? new AbortController() : null;
                let editTimeoutId = null;
                const editTimeout = new Promise(function (_resolve, reject) {
                    editTimeoutId = window.setTimeout(function () {
                        if (editController) editController.abort();
                        const error = new Error('Edit outcome could not be confirmed. Reload the conversation before retrying.');
                        error.name = 'TimeoutError';
                        reject(error);
                    }, 30000);
                });
                const editRequest = fetch('api/chat.php', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    credentials: 'include',
                    signal: editController ? editController.signal : undefined,
                    body: JSON.stringify({
                        action: 'edit_message',
                        message_id: messageId,
                        new_content: content
                    })
                }).then(function (response) {
                    return response.json();
                });
                Promise.race([editRequest, editTimeout])
                    .then(function (result) {
                        if (requestId !== editRequestId) {
                            return;
                        }
                        if (!result.success) {
                            throw new Error(result.message || 'Message could not be edited');
                        }
                        if (message) {
                            updateMessageText(message, content);
                        }
                        delete input.dataset.editMessageId;
                        input.value = draftBeforeEdit;
                        draftBeforeEdit = '';
                        input.placeholder = 'Type a message...';
                        input.dispatchEvent(new Event('input', {bubbles: true}));
                        saveChatDraft(state.activeChatKey, input.value);
                        if (typeof window.showToast === 'function') {
                            window.showToast('Message updated', 'success', 2200);
                        }
                    })
                    .catch(function (error) {
                        if (typeof window.showToast === 'function') {
                            const message = error && (error.name === 'AbortError' || error.name === 'TimeoutError')
                                ? 'Edit outcome could not be confirmed. Reload the conversation before retrying.'
                                : error.message;
                            window.showToast(message, 'error');
                        }
                    })
                    .finally(function () {
                        if (editTimeoutId !== null) window.clearTimeout(editTimeoutId);
                        if (requestId === editRequestId) {
                            editInFlight = false;
                            sendButton.replaceChildren(...originalButtonChildren);
                            sendButton.disabled = false;
                        }
                    });
            }

            function syncComposerLock() {
                const locked = sendButton.disabled;
                const voiceLocked = window.pmVoiceComposerBusy === true;
                input.readOnly = editInFlight || voiceLocked;
                input.setAttribute('aria-busy', String(editInFlight || voiceLocked));
                document.querySelectorAll('.composer-action, #attachmentPreview button').forEach(function (button) {
                    button.disabled = locked;
                    button.setAttribute('aria-disabled', String(locked));
                });
            }
        }

        function updateMessageText(message, value) {
            const content = message.querySelector('.message-content');
            if (!content) {
                return;
            }
            let body = content.querySelector(':scope > .message-text');
            if (body) {
                body.textContent = value;
            } else {
                body = document.createElement('div');
                body.className = 'message-text';
                body.textContent = value;
                const reply = content.querySelector(':scope > .reply-to');
                content.insertBefore(body, reply ? reply.nextSibling : content.firstChild);
            }
            if (!content.querySelector('.message-edited')) {
                const edited = document.createElement('span');
                edited.className = 'message-edited';
                edited.textContent = localized('chat.edited', {}, 'edited');
                edited.dataset.i18n = 'chat.edited';
                const time = content.querySelector('.message-time');
                content.insertBefore(edited, time || null);
            }
            if (content.hasAttribute('aria-haspopup')) {
                content.setAttribute('aria-label', createMessageActionLabel(content));
            }
        }

        function setupFileDropValidation() {
            if (!messagesContainer) {
                return;
            }

            messagesContainer.addEventListener('drop', function (event) {
                const file = event.dataTransfer && event.dataTransfer.files[0];
                if (!file) {
                    return;
                }
                let error = '';
                if (file.size < 1) {
                    error = 'Empty files cannot be sent';
                } else if (file.size > 50 * 1024 * 1024) {
                    error = 'Files must be smaller than 50 MB';
                } else if (typeof window.isSupportedChatAttachment !== 'function' ||
                    !window.isSupportedChatAttachment(file)) {
                    error = 'This file type is not supported';
                }
                if (!error) {
                    return;
                }
                event.preventDefault();
                event.stopImmediatePropagation();
                if (event.dataTransfer) {
                    event.dataTransfer.dropEffect = 'none';
                }
                if (typeof window.showToast === 'function') {
                    window.showToast(error, 'warning');
                }
            }, true);
        }

        function setupModalSafety() {
            document.querySelectorAll('.modal').forEach(function (modal) {
                const title = modal.querySelector('.modal-title');
                if (title) {
                    title.id = title.id || modal.id + 'Title';
                    modal.setAttribute('aria-labelledby', title.id);
                }
            });

            document.addEventListener('keydown', function (event) {
                const login = document.getElementById('loginModal');
                const loginIsOpen = login && login.classList.contains('show');
                const blockedShortcut = (event.ctrlKey || event.metaKey) &&
                    ['k', 'n'].includes(event.key.toLowerCase());
                if (loginIsOpen && (event.key === 'Escape' || blockedShortcut)) {
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    return;
                }

                const contextMenu = document.getElementById('contextMenu');
                if (event.key === 'Escape' && contextMenu && contextMenu.style.display !== 'none' &&
                    contextMenuOpener) {
                    window.setTimeout(function () {
                        if (contextMenuOpener && contextMenuOpener.isConnected) {
                            contextMenuOpener.focus({preventScroll: true});
                        }
                    }, 0);
                }
            }, true);

            document.addEventListener('show.bs.modal', function (event) {
                activeModalElement = event.target;
                activeModalOpening = true;
                if (document.activeElement && document.activeElement !== document.body) {
                    modalOpeners.set(event.target, document.activeElement);
                }
            });

            document.addEventListener('shown.bs.modal', function (event) {
                if (activeModalElement === event.target) {
                    activeModalOpening = false;
                }
            });

            document.addEventListener('hidden.bs.modal', function (event) {
                if (activeModalElement === event.target) {
                    activeModalElement = null;
                    activeModalOpening = false;
                }
                const opener = modalOpeners.get(event.target);
                window.setTimeout(function () {
                    restoreMobileSurfaceIfNeeded();
                    const visibleModal = document.querySelector('.modal.show');
                    const openerIsVisible = opener && opener.isConnected &&
                        !opener.closest('.modal:not(.show)') && !opener.closest('[inert]') &&
                        opener.getClientRects().length > 0;
                    if (!visibleModal && openerIsVisible && event.target.id !== 'loginModal') {
                        opener.focus({preventScroll: true});
                    } else if (!visibleModal && event.target.id !== 'loginModal') {
                        const candidates = mainContainer.classList.contains('settings-detail-mode')
                            ? [settingsContent && settingsContent.querySelector('.settings-detail-close'),
                                settingsContent && settingsContent.querySelector('.settings-back-btn')]
                            : (!chatContent.classList.contains('d-none')
                                ? [document.querySelector('.mobile-chat-back button'),
                                    document.getElementById('messageInput'),
                                    document.querySelector('.chat-search-button')]
                                : [searchInput, document.querySelector('[data-pm-action="chat-home"]')]);
                        const fallback = candidates.find(function (candidate) {
                            return candidate && candidate.isConnected && !candidate.closest('[inert]') &&
                                !candidate.closest('[aria-hidden="true"]') &&
                                candidate.getClientRects().length > 0 && !candidate.disabled;
                        });
                        if (fallback) fallback.focus({preventScroll: true});
                    }
                }, 0);
            });

            const userResults = document.getElementById('userSearchResults');
            if (userResults) {
                userResults.addEventListener('click', function (event) {
                    const resultItem = event.target.closest('.search-result-item, .chat-item');
                    if (!resultItem || resultItem.dataset.confirmTransitionReady === 'true') {
                        if (resultItem) {
                            delete resultItem.dataset.confirmTransitionReady;
                        }
                        return;
                    }
                    const modal = document.getElementById('newChatModal');
                    const instance = window.bootstrap && bootstrap.Modal.getInstance(modal);
                    if (!instance || !modal.classList.contains('show')) {
                        return;
                    }
                    event.preventDefault();
                    event.stopImmediatePropagation();
                    const transitionOpener = modalOpeners.get(modal);
                    modal.dataset.continueUserSelection = 'true';
                    modal.addEventListener('hidden.bs.modal', function continueAfterModalCloses() {
                        resultItem.dataset.confirmTransitionReady = 'true';
                        resultItem.click();
                        const confirmModal = document.getElementById('confirmModal');
                        if (transitionOpener && confirmModal) {
                            modalOpeners.set(confirmModal, transitionOpener);
                        }
                        delete modal.dataset.continueUserSelection;
                        modal.dispatchEvent(new CustomEvent('hi:reset-people-search'));
                    }, {once: true});
                    instance.hide();
                }, true);
            }
        }

        function restoreMobileSurfaceIfNeeded() {
            if (window.innerWidth > 768 || document.querySelector('.modal.show')) {
                return;
            }
            const chatContent = document.getElementById('chatContent');
            const welcome = document.getElementById('welcomeScreen');
            const content = document.getElementById('settingsContent');
            const listSurfaceVisible = sidebar.classList.contains('show') &&
                (!chatList.classList.contains('d-none') || !settingsList.classList.contains('d-none'));
            const allMainViewsHidden = chatContent.classList.contains('d-none') &&
                welcome.classList.contains('d-none') && (!content || content.classList.contains('d-none'));
            if (!listSurfaceVisible && allMainViewsHidden) {
                if (mainContainer && mainContainer.classList.contains('settings-mode')) {
                    enterSettingsRootSurface();
                } else if (typeof window.showChatsTab === 'function') {
                    window.showChatsTab();
                }
            }
        }

        function setupPeopleSearch() {
            const input = document.getElementById('userSearchInput');
            const results = document.getElementById('userSearchResults');
            if (!input || !results || typeof window.renderUserSearchResults !== 'function') {
                return;
            }

            let timer = 0;
            let controller = null;
            let sequence = 0;
            let lastQuery = '';
            window.searchUsers = function searchUsersWithDebounce() {
                const query = input.value.trim();
                if (query === lastQuery) {
                    return;
                }
                lastQuery = query;
                const requestSequence = ++sequence;
                window.clearTimeout(timer);
                if (controller) {
                    controller.abort();
                    controller = null;
                }
                if (query.length < 2) {
                    renderPeopleEmpty('Start with a name', 'Enter at least two characters to find someone.',
                        'fa-user-plus');
                    return;
                }
                if (query.length > 50) {
                    renderPeopleEmpty('Search is too long', 'Use fewer than 50 characters.', 'fa-text-width');
                    return;
                }

                timer = window.setTimeout(function () {
                    controller = new AbortController();
                    results.innerHTML = '<div class="modal-empty-state"><span><i class="fas fa-spinner fa-spin"></i>' +
                        '</span><strong>Searching</strong><p>Looking for people…</p></div>';
                    fetch('api/chat.php', {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        credentials: 'include',
                        signal: controller.signal,
                        body: JSON.stringify({action: 'search_users', query: query})
                    })
                        .then(function (response) { return response.json(); })
                        .then(function (result) {
                            if (requestSequence !== sequence) {
                                return;
                            }
                            if (!result.success) {
                                throw new Error(result.message || 'Search failed');
                            }
                            if (!result.users.length) {
                                renderPeopleEmpty('No people found', 'Try another name or username.', 'fa-user-slash');
                                return;
                            }
                            window.renderUserSearchResults(result.users);
                        })
                        .catch(function (error) {
                            if (error.name !== 'AbortError' && requestSequence === sequence) {
                                lastQuery = '';
                                renderPeopleEmpty('Search unavailable', 'Check your connection and try again.',
                                    'fa-wifi');
                            }
                        });
                }, 280);
            };

            const modal = document.getElementById('newChatModal');
            if (modal) {
                modal.addEventListener('hidden.bs.modal', function () {
                    resetPeopleSearch(modal.dataset.continueUserSelection !== 'true');
                });
                modal.addEventListener('hi:reset-people-search', function () {
                    resetPeopleSearch(true);
                });
            }

            function resetPeopleSearch(clearContent) {
                window.clearTimeout(timer);
                if (controller) {
                    controller.abort();
                    controller = null;
                }
                sequence += 1;
                lastQuery = '';
                if (clearContent) {
                    input.value = '';
                    renderPeopleEmpty('Start with a name', 'Enter at least two characters to find someone.',
                        'fa-user-plus');
                }
            }

            function renderPeopleEmpty(title, description, icon) {
                results.innerHTML = '<div class="modal-empty-state"><span><i class="fas ' + icon + '"></i></span>' +
                    '<strong></strong><p></p></div>';
                results.querySelector('strong').textContent = title;
                results.querySelector('p').textContent = description;
            }
        }

        function setupSearch() {
            if (searchShortcut) {
                const isApple = /Mac|iPhone|iPad/.test(navigator.platform);
                searchShortcut.textContent = isApple ? '⌘K' : 'Ctrl K';
                searchShortcut.classList.toggle('is-wide', !isApple);
            }

            searchInput.setAttribute('autocomplete', 'off');
            searchInput.setAttribute('aria-label', 'Search the current list');
            searchInput.setAttribute('aria-controls', 'chatList settingsList');
            searchInput.setAttribute('spellcheck', 'false');

            searchInput.addEventListener('input', function () {
                updateSearchChrome();
                filterVisibleList();
            });

            searchInput.addEventListener('keydown', function (event) {
                if (event.key === 'Escape' && searchInput.value) {
                    event.preventDefault();
                    event.stopPropagation();
                    clearSearch();
                    return;
                }
                if (event.key === 'ArrowDown') {
                    const firstItem = getVisibleChatItems()[0];
                    if (getCurrentView() === 'chats' && firstItem) {
                        event.preventDefault();
                        firstItem.focus({preventScroll: true});
                        firstItem.scrollIntoView({block: 'nearest', inline: 'nearest'});
                    }
                }
            });

            if (searchClear) {
                searchClear.addEventListener('click', clearSearch);
            }

            filterButtons.forEach(function (button) {
                button.addEventListener('click', function () {
                    state.conversationFilter = button.dataset.conversationFilter || 'all';
                    updateFilterButtons();
                    filterVisibleList();
                });
            });

            document.addEventListener('keydown', function (event) {
                if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') {
                    window.setTimeout(function () {
                        searchInput.select();
                    }, 0);
                }
            });
        }

        function setupChatListKeyboardNavigation() {
            chatList.setAttribute('role', 'listbox');
            chatList.setAttribute('aria-label', 'Conversations');
            window.refreshConversationRowStates = refreshConversationRowStates;
            window.syncConversationRovingTabStop = function syncConversationRovingTabStop() {
                syncChatListRovingTabStop();
            };

            chatList.addEventListener('keydown', function navigateConversationRows(event) {
                const item = event.target.closest && event.target.closest('.chat-item');
                const keys = ['ArrowDown', 'ArrowUp', 'Home', 'End'];
                if (!item || event.target !== item || item.parentElement !== chatList || !keys.includes(event.key) ||
                    event.altKey || event.ctrlKey || event.metaKey) {
                    return;
                }
                const items = getVisibleChatItems();
                if (!items.length) {
                    return;
                }
                const currentIndex = Math.max(0, items.indexOf(item));
                const nextIndex = event.key === 'Home' ? 0 :
                    event.key === 'End' ? items.length - 1 :
                        event.key === 'ArrowDown' ? Math.min(currentIndex + 1, items.length - 1) :
                            Math.max(currentIndex - 1, 0);
                event.preventDefault();
                const nextItem = items[nextIndex];
                state.focusedChatKey = getChatKey(nextItem);
                syncChatListRovingTabStop(nextItem);
                nextItem.focus({preventScroll: true});
                nextItem.scrollIntoView({block: 'nearest', inline: 'nearest'});
            });

            syncChatListRovingTabStop();
        }

        function getVisibleChatItems() {
            return Array.from(chatList.querySelectorAll(':scope > .chat-item')).filter(function (item) {
                return !item.hidden;
            });
        }

        function syncChatListRovingTabStop(preferredItem) {
            const items = Array.from(chatList.querySelectorAll(':scope > .chat-item'));
            const visibleItems = items.filter(function (item) { return !item.hidden; });
            let tabStop = preferredItem && visibleItems.includes(preferredItem) ? preferredItem : null;
            if (!tabStop && state.focusedChatKey) {
                tabStop = visibleItems.find(function (item) {
                    return getChatKey(item) === state.focusedChatKey;
                }) || null;
            }
            if (!tabStop) {
                tabStop = visibleItems.find(function (item) {
                    return item.classList.contains('active');
                }) || visibleItems[0] || null;
            }

            items.forEach(function (item) {
                const isActive = item.classList.contains('active');
                item.setAttribute('role', 'option');
                item.setAttribute('aria-selected', String(isActive));
                item.removeAttribute('aria-current');
                item.tabIndex = item === tabStop ? 0 : -1;
            });
        }

        function refreshConversationRowStates() {
            chatList.querySelectorAll(':scope > .chat-item').forEach(function (item) {
                const hasDraft = Boolean(chatDrafts.get(getChatKey(item)));
                if (hasDraft) {
                    item.dataset.hasDraft = 'true';
                } else {
                    delete item.dataset.hasDraft;
                }
            });
            syncChatListRovingTabStop();
            chatList.dispatchEvent(new CustomEvent('hi:conversation-row-states-refreshed'));
        }

        function clearSearch() {
            searchInput.value = '';
            updateSearchChrome();
            filterVisibleList();
            searchInput.focus();
        }

        function updateSearchChrome() {
            const hasQuery = searchInput.value.trim().length > 0;
            if (searchClear) {
                searchClear.hidden = !hasQuery;
            }
            if (searchShortcut) {
                searchShortcut.hidden = hasQuery;
            }
        }

        function updateFilterButtons() {
            filterButtons.forEach(function (button) {
                const isActive = button.dataset.conversationFilter === state.conversationFilter;
                button.classList.toggle('active', isActive);
                button.setAttribute('aria-pressed', String(isActive));
            });
        }

        function filterVisibleList() {
            const isSettings = getCurrentView() === 'settings';
            const list = isSettings ? settingsList : chatList;
            const itemSelector = isSettings ? '.settings-item' : '.chat-item';
            const items = Array.from(list.querySelectorAll(':scope > ' + itemSelector));
            const queryTokens = localeCaseFold(searchInput.value.trim()).split(/\s+/).filter(Boolean);
            let visibleCount = 0;

            items.forEach(function (item) {
                const searchableText = localeCaseFold(item.textContent);
                const matchesQuery = queryTokens.every(function (token) {
                    return searchableText.includes(token);
                });
                const matchesFilter = isSettings || state.conversationFilter !== 'unread' ||
                    Boolean(item.querySelector('.unread-count:not([hidden])'));
                const isVisible = matchesQuery && matchesFilter;
                item.hidden = !isVisible;
                if (isVisible) {
                    visibleCount += 1;
                }
            });

            updateUnreadCount(items);
            updateEmptyState(list, items.length, visibleCount, isSettings);
            if (!isSettings) {
                syncChatListRovingTabStop();
            }

            const hint = document.querySelector('.sidebar-section-hint');
            if (hint && !isSettings) {
                hint.textContent = (queryTokens.length || state.conversationFilter !== 'all')
                    ? localizedCount('chat.list.shown', visibleCount, visibleCount + ' shown')
                    : localizedLiteral('Recent');
            }
        }

        function updateUnreadCount(items) {
            const unreadCount = items.filter(function (item) {
                return Boolean(item.querySelector('.unread-count:not([hidden])'));
            }).length;
            const badge = document.getElementById('unreadFilterCount');
            if (badge) {
                badge.textContent = localizedNumber(unreadCount);
                badge.hidden = unreadCount === 0;
            }
        }

        function updateEmptyState(list, totalCount, visibleCount, isSettings) {
            let emptyState = list.querySelector(':scope > .sidebar-filter-empty');
            const shouldShow = totalCount > 0 && visibleCount === 0;

            if (!shouldShow) {
                if (emptyState) {
                    emptyState.remove();
                }
                return;
            }

            if (!emptyState) {
                emptyState = document.createElement('div');
                emptyState.className = 'sidebar-filter-empty';
                emptyState.setAttribute('role', 'status');
                emptyState.setAttribute('aria-live', 'polite');
                emptyState.innerHTML = '<span><i class="fas fa-search"></i></span>' +
                    '<strong>Nothing found</strong><p>Try another search or filter.</p>';
                list.appendChild(emptyState);
            }

            const label = emptyState.querySelector('strong');
            if (label) {
                label.textContent = isSettings
                    ? localized('settings.no_matching', {}, 'No matching settings')
                    : localized('chat.no_matching', {}, 'No matching conversations');
            }
        }

        function setupLoadingFallback() {
            scheduleFallback();

            function scheduleFallback() {
                window.setTimeout(showFallback, 9000);
            }

            function showFallback() {
                const skeleton = chatList.querySelector(':scope > .chat-list-skeleton');
                if (!skeleton) {
                    return;
                }

                const fallback = document.createElement('div');
                fallback.className = 'sidebar-load-error';
                fallback.setAttribute('role', 'status');
                fallback.innerHTML = '<span><i class="fas fa-wifi"></i></span>' +
                    '<strong>Could not load conversations</strong>' +
                    '<p>Check your connection and try again.</p>' +
                    '<button type="button" class="sidebar-retry-button">Try again</button>';
                skeleton.replaceWith(fallback);

                fallback.querySelector('button').addEventListener('click', function () {
                    const loading = document.createElement('div');
                    loading.className = 'chat-list-skeleton';
                    loading.setAttribute('aria-hidden', 'true');
                    loading.innerHTML = '<div class="skeleton-chat"><span></span><i></i><b></b></div>' +
                        '<div class="skeleton-chat"><span></span><i></i><b></b></div>' +
                        '<div class="skeleton-chat"><span></span><i></i><b></b></div>';
                    fallback.replaceWith(loading);
                    if (typeof window.loadChats === 'function') {
                        window.loadChats();
                    } else {
                        window.location.reload();
                    }
                    scheduleFallback();
                });
            }
        }

        function enhanceInteractiveElements(root) {
            const selector = '.chat-item, .settings-item, .attachment-option, .context-menu-item, ' +
                '.forward-chat-item, .search-result-item, .participant-item';
            const elements = [];
            if (root.matches && root.matches(selector)) {
                elements.push(root);
            }
            if (root.querySelectorAll) {
                elements.push(...root.querySelectorAll(selector));
            }
            elements.forEach(function (element) {
                if (element.classList.contains('chat-item') && element.parentElement === chatList) {
                    return;
                }
                if (!element.hasAttribute('tabindex')) {
                    element.setAttribute('tabindex', '0');
                }
                if (!element.hasAttribute('role')) {
                    element.setAttribute('role', 'button');
                }
                if (!element.hasAttribute('aria-label')) {
                    const label = element.textContent.replace(/\s+/g, ' ').trim();
                    if (label) {
                        element.setAttribute('aria-label', label);
                    }
                }
                if (element.dataset.keyboardReady === 'true') {
                    return;
                }
                element.dataset.keyboardReady = 'true';
                element.addEventListener('keydown', function (event) {
                    if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        element.click();
                    }
                });
            });
        }

        function enhanceMessageActions(root) {
            const menu = document.getElementById('contextMenu');
            if (menu && menu.dataset.keyboardMenuReady !== 'true') {
                menu.dataset.keyboardMenuReady = 'true';
                menu.setAttribute('role', 'menu');
                menu.setAttribute('data-i18n-aria-label', 'chat.message_actions');
                menu.setAttribute('aria-label', 'Message actions');
                menu.querySelectorAll('.context-menu-item').forEach(function (item) {
                    item.setAttribute('role', 'menuitem');
                });
                menu.querySelectorAll('.context-menu-divider').forEach(function (divider) {
                    divider.setAttribute('role', 'separator');
                });

                const syncMenuVisibility = function () {
                    menu.setAttribute('aria-hidden', String(menu.style.display === 'none'));
                };
                new MutationObserver(syncMenuVisibility).observe(menu, {
                    attributes: true,
                    attributeFilter: ['style']
                });
                syncMenuVisibility();

                menu.addEventListener('keydown', function (event) {
                    const items = getVisibleMenuItems();
                    if (!items.length) {
                        return;
                    }
                    const currentIndex = items.indexOf(document.activeElement);
                    let nextIndex = currentIndex;
                    if (event.key === 'ArrowDown') {
                        nextIndex = (currentIndex + 1) % items.length;
                    } else if (event.key === 'ArrowUp') {
                        nextIndex = (currentIndex - 1 + items.length) % items.length;
                    } else if (event.key === 'Home') {
                        nextIndex = 0;
                    } else if (event.key === 'End') {
                        nextIndex = items.length - 1;
                    } else if (event.key === 'Escape') {
                        event.preventDefault();
                        event.stopPropagation();
                        if (typeof window.hideContextMenu === 'function') {
                            window.hideContextMenu();
                        } else {
                            menu.style.display = 'none';
                        }
                        if (contextMenuOpener && contextMenuOpener.isConnected) {
                            contextMenuOpener.focus({preventScroll: true});
                        }
                        return;
                    } else {
                        return;
                    }
                    event.preventDefault();
                    items[nextIndex].focus({preventScroll: true});
                });
                menu.addEventListener('click', function () {
                    window.setTimeout(function () {
                        if (menu.style.display === 'none' && menu.contains(document.activeElement) &&
                            contextMenuOpener && contextMenuOpener.isConnected) {
                            contextMenuOpener.focus({preventScroll: true});
                        }
                    }, 0);
                });
            }

            const contents = [];
            if (root.matches && root.matches('.message-content')) {
                contents.push(root);
            }
            if (root.querySelectorAll) {
                contents.push(...root.querySelectorAll('.message-content'));
            }
            contents.forEach(function (content) {
                if (content.dataset.messageActionsReady === 'true') {
                    return;
                }
                content.dataset.messageActionsReady = 'true';
                content.tabIndex = 0;
                content.setAttribute('role', content.querySelector('.image-message-retry') ? 'group' : 'button');
                content.setAttribute('aria-haspopup', 'menu');
                content.setAttribute('aria-label', createMessageActionLabel(content));
                content.addEventListener('contextmenu', function () {
                    contextMenuOpener = content;
                }, true);
                content.addEventListener('keydown', function (event) {
                    if (event.target !== content && event.target.closest('button, a, input, select, textarea')) {
                        return;
                    }
                    const opensMenu = event.key === 'Enter' || event.key === ' ' ||
                        event.key === 'ContextMenu' || (event.shiftKey && event.key === 'F10');
                    if (!opensMenu) {
                        return;
                    }
                    event.preventDefault();
                    event.stopPropagation();
                    const sendButton = document.querySelector('.send-btn');
                    if (sendButton && sendButton.disabled) {
                        return;
                    }
                    contextMenuOpener = content;
                    const bounds = content.getBoundingClientRect();
                    content.dispatchEvent(new MouseEvent('contextmenu', {
                        bubbles: true,
                        cancelable: true,
                        clientX: Math.min(bounds.left + 24, window.innerWidth - 24),
                        clientY: Math.min(bounds.bottom, window.innerHeight - 24)
                    }));
                    window.setTimeout(function () {
                        const firstItem = getVisibleMenuItems()[0];
                        if (firstItem) {
                            firstItem.focus({preventScroll: true});
                        }
                    }, 70);
                });
            });

            function getVisibleMenuItems() {
                if (!menu || menu.style.display === 'none') {
                    return [];
                }
                return Array.from(menu.querySelectorAll('.context-menu-item')).filter(function (item) {
                    return !item.hidden && item.style.display !== 'none';
                });
            }
        }

        function createMessageActionLabel(content) {
            const previewNode = content.querySelector(':scope > .message-text') ||
                content.querySelector(':scope > .message-caption') ||
                content.querySelector(
                    ':scope > .file-message .file-name, ' +
                    ':scope > .audio-message .file-name, ' +
                    ':scope > .video-message .file-name, ' +
                    ':scope > .image-message .image-message-unavailable-name'
                );
            let preview = '';
            if (previewNode && !previewNode.hasAttribute('data-i18n-fallback') &&
                !previewNode.hasAttribute('data-i18n-image-fallback')) {
                preview = previewNode.textContent;
            }
            if (!preview) {
                const image = content.querySelector(':scope > .image-message img');
                if (image && image.dataset.i18nFileNameFallback !== 'true') {
                    preview = image.getAttribute('alt') || '';
                }
            }
            preview = String(preview).replace(/\s+/g, ' ').trim().slice(0, 140);
            return preview
                ? localized(
                    'chat.message_action_label',
                    {preview: preview},
                    'Message: {{preview}}. Open actions with Enter or Shift plus F10.'
                ).replace('{{preview}}', function () { return preview; })
                : localized(
                    'chat.message_action_label_empty',
                    {},
                    'Message. Open actions with Enter or Shift plus F10.'
                );
        }

        function enhancePasswordFields(root) {
            root.querySelectorAll('input[type="password"]:not([data-password-enhanced])').forEach(function (input) {
                input.dataset.passwordEnhanced = 'true';
                if (!input.autocomplete) {
                    const id = input.id.toLocaleLowerCase();
                    input.autocomplete = id.includes('current') || id.includes('login')
                        ? 'current-password'
                        : 'new-password';
                }
                const wrapper = document.createElement('div');
                wrapper.className = 'password-field';
                input.parentNode.insertBefore(wrapper, input);
                wrapper.appendChild(input);

                const toggle = document.createElement('button');
                toggle.type = 'button';
                toggle.className = 'password-visibility-toggle';
                toggle.setAttribute('data-i18n-aria-label', 'auth.show_password');
                toggle.setAttribute('aria-label', 'Show password');
                toggle.setAttribute('aria-pressed', 'false');
                toggle.innerHTML = '<i class="fas fa-eye"></i>';
                wrapper.appendChild(toggle);

                toggle.addEventListener('click', function () {
                    const reveal = input.type === 'password';
                    input.type = reveal ? 'text' : 'password';
                    toggle.setAttribute('data-i18n-aria-label', reveal ? 'auth.hide_password' : 'auth.show_password');
                    toggle.setAttribute('aria-label', reveal ? 'Hide password' : 'Show password');
                    toggle.setAttribute('aria-pressed', String(reveal));
                    toggle.innerHTML = reveal
                        ? '<i class="fas fa-eye-slash"></i>'
                        : '<i class="fas fa-eye"></i>';
                    input.focus({preventScroll: true});
                });
            });
        }

        function enhanceAppearanceControls(root) {
            if (settingsContentArea) {
                settingsContentArea.classList.toggle('appearance-content-grid',
                    Boolean(settingsContentArea.querySelector('#darkModeToggle')));
            }
            const themeToggle = root.querySelector && root.querySelector('#darkModeToggle:not([data-visual-enhanced])');
            if (themeToggle) {
                themeToggle.dataset.visualEnhanced = 'true';
                const option = themeToggle.closest('.settings-option');
                const nativeToggle = themeToggle.closest('.settings-toggle');
                if (nativeToggle) {
                    nativeToggle.classList.add('appearance-native-control');
                }
                if (option) {
                    option.classList.add('appearance-theme-option');
                    const choices = document.createElement('div');
                    choices.className = 'theme-choice-grid';
                    choices.innerHTML = createThemeChoice('light', 'Light', 'Bright and calm') +
                        createThemeChoice('dark', 'Dark', 'Focused and low-glare');
                    option.insertAdjacentElement('afterend', choices);
                    choices.querySelectorAll('[data-theme-value]').forEach(function (button) {
                        button.addEventListener('click', function () {
                            const wantsDark = button.dataset.themeValue === 'dark';
                            themeToggle.checked = wantsDark;
                            themeToggle.dispatchEvent(new Event('change', {bubbles: true}));
                            syncVisualAppearanceControls();
                        });
                    });
                }
            }

            const fontSize = root.querySelector && root.querySelector('#fontSize:not([data-visual-enhanced])');
            if (fontSize) {
                enhanceSelectChoices(fontSize, 'font');
            }

            const chatBackground = root.querySelector &&
                root.querySelector('#chatBackground:not([data-visual-enhanced])');
            if (chatBackground) {
                enhanceSelectChoices(chatBackground, 'background');
            }

            syncVisualAppearanceControls();
        }

        function createThemeChoice(value, label, description) {
            return '<button type="button" class="theme-choice" data-theme-value="' + value + '" ' +
                'aria-pressed="false"><span class="theme-choice-preview theme-choice-' + value + '">' +
                '<i></i><b></b><em></em></span><span><strong>' + label + '</strong><small>' +
                description + '</small></span><i class="fas fa-check"></i></button>';
        }

        function enhanceSelectChoices(select, type) {
            select.dataset.visualEnhanced = 'true';
            select.classList.add('appearance-native-select');
            const group = select.closest('.settings-input-group');
            if (!group) {
                return;
            }
            group.classList.add('visual-choice-group');
            const choices = document.createElement('div');
            choices.className = 'visual-choice-grid visual-choice-' + type;

            Array.from(select.options).forEach(function (option) {
                const button = document.createElement('button');
                const semanticLabel = option.dataset.i18n || '';
                const optionLabel = semanticLabel
                    ? localized(semanticLabel, {}, option.textContent)
                    : option.textContent;
                button.type = 'button';
                button.className = 'visual-choice';
                button.dataset.appearanceTarget = select.id;
                button.dataset.appearanceValue = option.value;
                if (semanticLabel) button.dataset.i18nAppearanceLabel = semanticLabel;
                button.setAttribute('aria-pressed', 'false');
                button.setAttribute('aria-label', optionLabel);
                if (type === 'font') {
                    button.innerHTML = '<span class="font-choice-sample font-choice-' + option.value + '">Aa</span>' +
                        '<strong>' + optionLabel + '</strong><i class="fas fa-check"></i>';
                } else {
                    button.innerHTML = '<span class="background-choice-swatch background-choice-' + option.value +
                        '"><i></i><b></b></span><strong>' + optionLabel +
                        '</strong><i class="fas fa-check"></i>';
                }
                button.addEventListener('click', function () {
                    select.value = option.value;
                    select.dispatchEvent(new Event('change', {bubbles: true}));
                    syncVisualAppearanceControls();
                });
                choices.appendChild(button);
            });

            group.appendChild(choices);
        }

        function syncVisualAppearanceControls() {
            const isLight = document.body.classList.contains('light-mode');
            const themeToggle = document.getElementById('darkModeToggle');
            if (themeToggle) {
                themeToggle.checked = !isLight;
            }
            document.querySelectorAll('[data-theme-value]').forEach(function (button) {
                const selected = button.dataset.themeValue === (isLight ? 'light' : 'dark');
                button.classList.toggle('selected', selected);
                button.setAttribute('aria-pressed', String(selected));
            });
            document.querySelectorAll('[data-appearance-target]').forEach(function (button) {
                const select = document.getElementById(button.dataset.appearanceTarget);
                const selected = Boolean(select && select.value === button.dataset.appearanceValue);
                button.classList.toggle('selected', selected);
                button.setAttribute('aria-pressed', String(selected));
            });
        }

        function refreshVisualChoiceLabels() {
            document.querySelectorAll('[data-appearance-target][data-appearance-value]').forEach(function (button) {
                const select = document.getElementById(button.dataset.appearanceTarget);
                if (!select) return;
                const option = Array.from(select.options).find(function (candidate) {
                    return candidate.value === button.dataset.appearanceValue;
                });
                if (!option) return;
                const semanticLabel = button.dataset.i18nAppearanceLabel || option.dataset.i18n || '';
                const label = semanticLabel
                    ? localized(semanticLabel, {}, option.textContent)
                    : option.textContent;
                button.setAttribute('aria-label', label);
                const output = button.querySelector('strong');
                if (output) output.textContent = label;
            });
        }

        function setupAvatarFallbacks() {
            document.addEventListener('error', function (event) {
                const image = event.target;
                if (!image || image.tagName !== 'IMG' || !image.closest) {
                    return;
                }
                const avatar = image.closest(avatarContainerSelector);
                if (avatar) {
                    showAvatarFallback(avatar, image);
                }
            }, true);
        }

        function setupImageAttachmentFallbacks() {
            document.addEventListener('error', function (event) {
                const image = event.target;
                if (!image || image.tagName !== 'IMG' || !image.matches) {
                    return;
                }
                if (image.matches('#previewImage')) {
                    showPreviewImageFailure(image);
                } else if (image.matches('.image-message img')) {
                    showInlineImageFailure(image);
                }
            }, true);

            document.addEventListener('load', function (event) {
                const image = event.target;
                if (!image || image.tagName !== 'IMG' || !image.matches) {
                    return;
                }
                if (image.matches('#previewImage')) {
                    markPreviewImageReady(image);
                } else if (image.matches('.image-message img')) {
                    image.removeAttribute('aria-busy');
                    const imageMessage = image.closest('.image-message');
                    if (imageMessage) {
                        imageMessage.classList.remove('image-message-failed');
                    }
                    syncAttachmentMessageRole(image.closest('.message-content'));
                }
            }, true);

            const originalShowImagePreview = window.showImagePreview;
            if (typeof originalShowImagePreview === 'function' &&
                originalShowImagePreview.imageAttachmentEnhanced !== true) {
                const enhancedShowImagePreview = function (source) {
                    const previewImage = document.getElementById('previewImage');
                    const trigger = window.event && window.event.currentTarget &&
                        window.event.currentTarget.matches && window.event.currentTarget.matches('.image-message img')
                        ? window.event.currentTarget
                        : null;
                    const filename = getAttachmentFilename(trigger, source);
                    if (previewImage) {
                        resetPreviewImageState(previewImage, source, filename);
                    }
                    return originalShowImagePreview.call(this, addImageRetryToken(source));
                };
                enhancedShowImagePreview.imageAttachmentEnhanced = true;
                window.showImagePreview = enhancedShowImagePreview;
            }
        }

        function enhanceImageAttachment(image) {
            if (!image || image.dataset.attachmentEnhanced === 'true') {
                return;
            }
            image.dataset.attachmentEnhanced = 'true';
            image.setAttribute('decoding', 'async');
            image.setAttribute('draggable', 'false');
            if (image.complete && image.naturalWidth === 0) {
                showInlineImageFailure(image);
            }
        }

        function showInlineImageFailure(image) {
            const imageMessage = image && image.closest('.image-message');
            if (!imageMessage || imageMessage.querySelector('.image-message-unavailable')) {
                return;
            }

            const source = image.dataset.attachmentOriginalSrc || image.getAttribute('src') || image.currentSrc || '';
            const filename = getAttachmentFilename(image, source);
            const failedImage = image.cloneNode(true);
            const fallback = document.createElement('div');
            const icon = document.createElement('span');
            const copy = document.createElement('span');
            const title = document.createElement('strong');
            const filenameElement = document.createElement('span');
            const retry = document.createElement('button');

            fallback.className = 'image-message-unavailable';
            fallback.setAttribute('role', 'group');
            fallback.setAttribute('aria-live', 'polite');
            fallback.dataset.i18nImageFilename = filename;

            icon.className = 'image-message-unavailable-icon';
            icon.setAttribute('aria-hidden', 'true');
            icon.innerHTML = '<i class="fas fa-image"></i>';

            copy.className = 'image-message-unavailable-copy';
            title.textContent = localized('files.photo_unavailable', {}, 'Photo unavailable');
            title.dataset.i18n = 'files.photo_unavailable';
            filenameElement.className = 'image-message-unavailable-name';
            filenameElement.dir = 'auto';
            if (filename) {
                filenameElement.textContent = filename;
                filenameElement.dataset.i18nIgnore = '';
            } else {
                filenameElement.dataset.i18nImageFallback = 'files.photo_failed';
            }
            copy.append(title, filenameElement);

            retry.type = 'button';
            retry.className = 'image-message-retry';
            retry.dataset.i18nRetryFilename = filename;
            retry.innerHTML = '<i class="fas fa-rotate-right" aria-hidden="true"></i><span>Try again</span>';
            retry.addEventListener('click', function (event) {
                event.preventDefault();
                event.stopPropagation();

                const retryImage = failedImage.cloneNode(true);
                retryImage.removeAttribute('src');
                retryImage.removeAttribute('onclick');
                delete retryImage.dataset.attachmentEnhanced;
                retryImage.dataset.attachmentOriginalSrc = source;
                retryImage.setAttribute('aria-busy', 'true');
                retryImage.addEventListener('click', function () {
                    if (typeof window.showImagePreview === 'function') {
                        window.showImagePreview(source);
                    }
                });

                imageMessage.classList.remove('image-message-failed');
                fallback.replaceWith(retryImage);
                syncAttachmentMessageRole(retryImage.closest('.message-content'));
                retryImage.setAttribute('src', addImageRetryToken(source));
            });

            fallback.append(icon, copy, retry);
            refreshImageFailureTranslations(fallback);
            imageMessage.classList.add('image-message-failed');
            image.replaceWith(fallback);
            syncAttachmentMessageRole(fallback.closest('.message-content'));
        }

        function resetPreviewImageState(image, source, filename) {
            const modal = image.closest('#imagePreviewModal');
            const body = image.closest('.modal-body');
            if (modal) {
                modal.classList.remove('image-preview-failed');
                modal.classList.add('image-preview-loading');
            }
            if (body) {
                body.setAttribute('aria-busy', 'true');
                const oldFallback = body.querySelector('.image-preview-unavailable');
                if (oldFallback) {
                    oldFallback.remove();
                }
            }
            image.hidden = false;
            image.removeAttribute('aria-hidden');
            image.dataset.attachmentOriginalSrc = source || '';
            image.dataset.attachmentFilename = filename || '';
            image.alt = filename ? 'Preview of ' + filename : 'Photo preview';
        }

        function showPreviewImageFailure(image) {
            const modal = image.closest('#imagePreviewModal');
            const body = image.closest('.modal-body');
            if (!body || body.querySelector('.image-preview-unavailable')) {
                return;
            }

            const source = image.dataset.attachmentOriginalSrc || image.getAttribute('src') || '';
            const filename = image.dataset.attachmentFilename || getAttachmentFilename(image, source);
            const fallback = document.createElement('div');
            const icon = document.createElement('span');
            const title = document.createElement('strong');
            const description = document.createElement('span');
            const filenameElement = document.createElement('span');
            const retry = document.createElement('button');

            if (modal) {
                modal.classList.remove('image-preview-loading');
                modal.classList.add('image-preview-failed');
            }
            body.removeAttribute('aria-busy');
            image.hidden = true;
            image.setAttribute('aria-hidden', 'true');

            fallback.className = 'image-preview-unavailable';
            fallback.setAttribute('role', 'status');
            fallback.setAttribute('aria-live', 'polite');

            icon.className = 'image-preview-unavailable-icon';
            icon.setAttribute('aria-hidden', 'true');
            icon.innerHTML = '<i class="fas fa-image"></i>';
            title.textContent = localized('files.photo_unavailable', {}, 'Photo unavailable');
            title.dataset.i18n = 'files.photo_unavailable';
            description.textContent = localized(
                'files.photo_removed',
                {},
                'It may have been removed, or the connection may have failed.'
            );
            description.dataset.i18n = 'files.photo_removed';
            filenameElement.className = 'image-preview-unavailable-name';
            filenameElement.dir = 'auto';
            if (filename) {
                filenameElement.textContent = filename;
                filenameElement.dataset.i18nIgnore = '';
            } else {
                filenameElement.dataset.i18nImageFallback = 'files.photo';
            }

            retry.type = 'button';
            retry.className = 'image-preview-retry';
            retry.dataset.i18nRetryFilename = filename;
            retry.innerHTML = '<i class="fas fa-rotate-right" aria-hidden="true"></i><span>Try again</span>';
            retry.addEventListener('click', function () {
                resetPreviewImageState(image, source, filename);
                image.setAttribute('src', addImageRetryToken(source));
            });

            fallback.append(icon, title, description, filenameElement, retry);
            refreshImageFailureTranslations(fallback);
            body.appendChild(fallback);
        }

        function refreshImageFailureTranslations(scope) {
            const root = scope && typeof scope.querySelectorAll === 'function' ? scope : document;
            const fallbackNodes = [];
            if (root instanceof Element && root.matches('[data-i18n-image-fallback]')) fallbackNodes.push(root);
            fallbackNodes.push(...root.querySelectorAll('[data-i18n-image-fallback]'));
            fallbackNodes.forEach(function (element) {
                element.textContent = localized(element.dataset.i18nImageFallback, {}, element.textContent);
            });

            const retryButtons = [];
            if (root instanceof Element && root.matches('[data-i18n-retry-filename]')) retryButtons.push(root);
            retryButtons.push(...root.querySelectorAll('[data-i18n-retry-filename]'));
            retryButtons.forEach(function (button) {
                const filename = button.dataset.i18nRetryFilename;
                const name = filename || localized('files.this_photo', {}, 'this photo');
                button.setAttribute('aria-label', localized(
                    'files.try_loading',
                    {name: name},
                    'Try loading ' + name + ' again'
                ));
            });

            const groups = [];
            if (root instanceof Element && root.matches('[data-i18n-image-filename]')) groups.push(root);
            groups.push(...root.querySelectorAll('[data-i18n-image-filename]'));
            groups.forEach(function (group) {
                const filename = group.dataset.i18nImageFilename;
                group.setAttribute('aria-label', filename
                    ? localized(
                        'files.photo_unavailable_named',
                        {name: filename},
                        'Photo unavailable: ' + filename
                    )
                    : localized('files.photo_unavailable', {}, 'Photo unavailable'));
            });
        }

        function markPreviewImageReady(image) {
            const modal = image.closest('#imagePreviewModal');
            const body = image.closest('.modal-body');
            if (modal) {
                modal.classList.remove('image-preview-loading', 'image-preview-failed');
            }
            if (body) {
                body.removeAttribute('aria-busy');
                const fallback = body.querySelector('.image-preview-unavailable');
                if (fallback) {
                    fallback.remove();
                }
            }
            image.hidden = false;
            image.removeAttribute('aria-hidden');
        }

        function getAttachmentFilename(image, source) {
            let filename = image && image.getAttribute ? image.getAttribute('alt') || '' : '';
            if (!filename || /^(preview|photo preview)$/i.test(filename.trim())) {
                try {
                    const pathname = new URL(source || '', window.location.href).pathname;
                    filename = decodeURIComponent(pathname.split('/').pop() || '');
                } catch (error) {
                    filename = '';
                }
            }
            return filename
                .replace(/^[a-f0-9]{13}_/i, '')
                .replace(/[\u0000-\u001f\u007f]/g, '')
                .replace(/\s+/g, ' ')
                .trim()
                .slice(0, 160);
        }

        function addImageRetryToken(source) {
            if (!source || /^(?:data|blob):/i.test(source)) {
                return source;
            }
            try {
                const url = new URL(source, window.location.href);
                // Keep retry URLs inside the strict attachment URL allowlist.
                // The value is cache-busting metadata only; the PHP endpoint
                // authorizes access from the numeric message id.
                url.searchParams.set('_retry', Date.now().toString());
                return url.href;
            } catch (error) {
                return source;
            }
        }

        function syncAttachmentMessageRole(content) {
            if (!content) {
                return;
            }
            content.setAttribute('role', content.querySelector('.image-message-retry') ? 'group' : 'button');
            if (typeof createMessageActionLabel === 'function') {
                content.setAttribute('aria-label', createMessageActionLabel(content));
            }
        }

        function decorateAvatars(root) {
            const avatars = [];
            if (root.matches && root.matches(avatarContainerSelector)) {
                avatars.push(root);
            }
            if (root.querySelectorAll) {
                avatars.push(...root.querySelectorAll(avatarContainerSelector));
            }

            avatars.forEach(function (avatar) {
                const image = avatar.querySelector('img');
                if (image) {
                    const sourceKey = getAvatarSourceKey(image);
                    if ((sourceKey && failedAvatarUrls.has(sourceKey)) ||
                        (image.complete && image.naturalWidth === 0)) {
                        showAvatarFallback(avatar, image);
                        return;
                    }

                    avatar.classList.remove('avatar-fallback-active');
                    avatar.classList.add('avatar-image-active');
                    avatar.querySelectorAll('.avatar-fallback').forEach(function (fallback) {
                        fallback.remove();
                    });
                    image.alt = '';
                    image.setAttribute('aria-hidden', 'true');
                    image.setAttribute('draggable', 'false');
                    avatar.style.removeProperty('--avatar-bg');
                    avatar.style.removeProperty('--avatar-color');
                    enhanceAvatarControl(avatar);
                    return;
                }

                avatar.classList.remove('avatar-image-active');
                applyAvatarPalette(avatar, getAvatarName(avatar));
                enhanceAvatarControl(avatar);
            });
        }

        function showAvatarFallback(avatar, image) {
            const name = getAvatarName(avatar, image);
            const sourceKey = getAvatarSourceKey(image);
            if (sourceKey && !sourceKey.startsWith('data:') && !sourceKey.startsWith('blob:')) {
                failedAvatarUrls.add(sourceKey);
            }

            if (image && image.parentElement) {
                image.remove();
            }

            let fallback = avatar.querySelector('.avatar-fallback');
            if (!fallback) {
                fallback = document.createElement('span');
                fallback.className = 'avatar-fallback';
                fallback.setAttribute('aria-hidden', 'true');
                const overlay = avatar.querySelector('.avatar-upload-overlay');
                avatar.insertBefore(fallback, overlay || avatar.firstChild);
            }
            fallback.textContent = getAvatarInitials(name);
            avatar.classList.remove('avatar-image-active');
            avatar.classList.add('avatar-fallback-active');
            applyAvatarPalette(avatar, name);
            enhanceAvatarControl(avatar);
        }

        function getAvatarSourceKey(image) {
            if (!image) {
                return '';
            }
            const source = image.currentSrc || image.getAttribute('src') || '';
            if (!source) {
                return '';
            }
            try {
                return new URL(source, window.location.href).href;
            } catch (error) {
                return source;
            }
        }

        function getAvatarName(avatar, image) {
            const textFrom = function (selector, root) {
                const element = (root || document).querySelector(selector);
                return element ? element.textContent.replace(/\s+/g, ' ').trim() : '';
            };

            if (avatar.id === 'userAvatar') {
                return textFrom('#userName') || 'You';
            }
            if (avatar.id === 'chatAvatar') {
                return textFrom('#chatTitle') || 'Chat';
            }
            if (avatar.id === 'profileAvatarLarge') {
                return textFrom('#profileNameLarge') || textFrom('#userName') || 'You';
            }

            const context = avatar.closest('.chat-item, .search-result-item, .participant-item, ' +
                '.forward-chat-item, .user-profile-header, .modal, .message');
            if (context) {
                const contextualName = textFrom('.chat-name, .participant-name, .forward-chat-name, ' +
                    '.user-profile-name, .user-name-large, [data-avatar-name]', context);
                if (contextualName) {
                    return contextualName;
                }
                if (context.classList.contains('message')) {
                    return textFrom('#chatTitle') || 'Contact';
                }
            }

            const suppliedName = avatar.dataset.avatarName || (image && image.getAttribute('alt')) || '';
            if (suppliedName && !/^(avatar|profile (?:photo|picture)|loading\.{0,3})$/i.test(suppliedName.trim())) {
                return suppliedName.trim();
            }
            return avatar.textContent.replace(/\s+/g, ' ').trim() || avatar.id || 'Contact';
        }

        function getAvatarInitials(name) {
            const words = String(name || '')
                .replace(/^@/, '')
                .trim()
                .split(/[\s_-]+/)
                .filter(Boolean);
            if (!words.length) {
                return '?';
            }
            const first = Array.from(words[0])[0] || '';
            const last = words.length > 1 ? (Array.from(words[words.length - 1])[0] || '') : '';
            return (first + last).toLocaleUpperCase();
        }

        function applyAvatarPalette(avatar, key) {
            const palette = [
                ['#173d4b', '#85e7cf'],
                ['#2f365f', '#b7c2ff'],
                ['#523a2d', '#ffd19c'],
                ['#4c3040', '#ffb3ca'],
                ['#273f35', '#a8e7bc'],
                ['#3d3152', '#d5b9ff']
            ];
            const hash = Array.from(key || 'Messenger').reduce(function (total, character) {
                return ((total << 5) - total + character.charCodeAt(0)) | 0;
            }, 0);
            const colors = palette[Math.abs(hash) % palette.length];
            avatar.style.setProperty('--avatar-bg', colors[0]);
            avatar.style.setProperty('--avatar-color', colors[1]);
        }

        function enhanceAvatarControl(avatar) {
            if (!avatar.hasAttribute('onclick') || avatar.dataset.avatarKeyboardReady === 'true') {
                return;
            }
            avatar.dataset.avatarKeyboardReady = 'true';
            avatar.setAttribute('role', 'button');
            avatar.setAttribute('tabindex', '0');
            avatar.addEventListener('keydown', function (event) {
                if (event.key === 'Enter' || event.key === ' ') {
                    event.preventDefault();
                    avatar.click();
                }
            });
        }

        function decorateMessages() {
            const heightBefore = messagesContainer ? messagesContainer.scrollHeight : 0;
            const scrollTopBefore = messagesContainer ? messagesContainer.scrollTop : 0;
            const distanceFromBottom = messagesContainer
                ? heightBefore - scrollTopBefore - messagesContainer.clientHeight
                : 0;
            const preserveViewport = scrollTopBefore > 1 && distanceFromBottom > 100;
            const messages = Array.from(messagesList.querySelectorAll(':scope > .message'));
            messages.forEach(function (message, index) {
                message.querySelectorAll('.image-message img').forEach(enhanceImageAttachment);
                const previous = messages[index - 1];
                const next = messages[index + 1];
                const groupedWithPrevious = messagesCanCluster(previous, message);
                const groupedWithNext = messagesCanCluster(message, next);

                message.classList.toggle('grouped-with-previous', groupedWithPrevious);
                message.classList.toggle('grouped-with-next', groupedWithNext);
            });

            if (preserveViewport && messagesContainer) {
                const heightDelta = messagesContainer.scrollHeight - heightBefore;
                if (heightDelta) {
                    messagesContainer.scrollTop = scrollTopBefore + heightDelta;
                }
            }
        }

        function messagesCanCluster(first, second) {
            if (!first || !second) {
                return false;
            }
            const firstDirection = first.classList.contains('outgoing') ? 'outgoing' : 'incoming';
            const secondDirection = second.classList.contains('outgoing') ? 'outgoing' : 'incoming';
            if (firstDirection !== secondDirection || getMessageSenderKey(first) !== getMessageSenderKey(second)) {
                return false;
            }

            const firstTime = getMessageTimeMinutes(first);
            const secondTime = getMessageTimeMinutes(second);
            return firstTime !== null && secondTime !== null && secondTime >= firstTime &&
                secondTime - firstTime <= 10;
        }

        function getMessageSenderKey(message) {
            if (message.classList.contains('outgoing')) {
                return 'outgoing';
            }
            const avatar = message.querySelector(':scope > .sender-avatar');
            if (!avatar) {
                return 'incoming-unknown';
            }
            const image = avatar.querySelector('img');
            return avatar.getAttribute('onclick') || (image && image.currentSrc) ||
                avatar.textContent.replace(/\s+/g, ' ').trim() || 'incoming-unknown';
        }

        function getMessageTimeMinutes(message) {
            if (message.dataset.createdAt) {
                const createdAt = typeof window.parsePmTimestamp === 'function'
                    ? window.parsePmTimestamp(message.dataset.createdAt)
                    : new Date(message.dataset.createdAt);
                if (createdAt instanceof Date && !Number.isNaN(createdAt.getTime())) {
                    return createdAt.getHours() * 60 + createdAt.getMinutes();
                }
            }
            const time = message.querySelector('.message-time');
            const value = time ? time.textContent.trim().toUpperCase() : '';
            const match = value.match(/(\d{1,2}):(\d{2})(?:\s*([AP])\.?M\.?)?/);
            if (!match) {
                return null;
            }
            let hours = Number(match[1]);
            const minutes = Number(match[2]);
            if (match[3] === 'A' && hours === 12) {
                hours = 0;
            } else if (match[3] === 'P' && hours < 12) {
                hours += 12;
            }
            return hours * 60 + minutes;
        }

        function mutationTouchesMessage(mutation) {
            return Array.from(mutation.addedNodes).concat(Array.from(mutation.removedNodes)).some(function (node) {
                return node.nodeType === Node.ELEMENT_NODE &&
                    (node.matches('.message') || Boolean(node.querySelector('.message')));
            });
        }

        function getChatKey(item) {
            if (item && item.dataset.chatId) {
                return 'chat:' + item.dataset.chatId;
            }
            const name = item && item.querySelector('.chat-name');
            return name ? name.textContent.replace(/\s+/g, ' ').trim().toLocaleLowerCase() : '';
        }

        function tagChatItems() {
            const items = Array.from(chatList.querySelectorAll(':scope > .chat-item'));
            items.forEach(function (item) {
                if (state.activeChatKey && getChatKey(item) === state.activeChatKey) {
                    selectedChatElement = item;
                }
            });
            syncChatListRovingTabStop();
            restorePendingHistoryChat();
        }

        function saveChatDraft(chatKey, value) {
            if (!chatKey) {
                return;
            }
            if (value) {
                chatDrafts.set(chatKey, value);
            } else {
                chatDrafts.delete(chatKey);
            }
            refreshConversationRowStates();
        }

        function captureRemovedChatState(mutation) {
            Array.from(mutation.removedNodes).forEach(function (node) {
                if (node.nodeType !== Node.ELEMENT_NODE) {
                    return;
                }
                const removedItems = node.matches('.chat-item')
                    ? [node]
                    : Array.from(node.querySelectorAll('.chat-item'));
                removedItems.forEach(function (item) {
                    if (item.classList.contains('active')) {
                        state.activeChatKey = getChatKey(item);
                    }
                });
            });
        }

        function restoreChatState() {
            const items = Array.from(chatList.querySelectorAll(':scope > .chat-item'));
            const activeItem = state.activeChatKey
                ? items.find(function (item) { return getChatKey(item) === state.activeChatKey; })
                : null;
            if (activeItem) {
                activeItem.classList.add('active');
            }

            const focusedItem = state.focusedChatKey
                ? items.find(function (item) { return getChatKey(item) === state.focusedChatKey; })
                : null;
            if (focusedItem && document.activeElement === document.body) {
                focusedItem.focus({preventScroll: true});
            }
            syncCurrentStates();
            refreshConversationRowStates();
        }

        function setupJumpToLatest() {
            if (!messagesContainer) {
                return;
            }

            jumpButton = document.createElement('button');
            jumpButton.type = 'button';
            jumpButton.className = 'jump-to-latest';
            jumpButton.hidden = true;
            jumpButton.setAttribute('data-i18n-aria-label', 'chat.jump_latest');
            jumpButton.setAttribute('aria-label', 'Jump to latest message');
            jumpButton.innerHTML = '<i class="fas fa-arrow-down"></i><span>Latest</span>';
            jumpButton.querySelector('span').setAttribute('data-i18n', 'chat.latest');
            document.getElementById('chatContent').appendChild(jumpButton);

            jumpButton.addEventListener('click', function () {
                if (typeof window.exitSearchContextReview === 'function') {
                    window.exitSearchContextReview();
                }
                messagesContainer.scrollTo({top: messagesContainer.scrollHeight, behavior: 'smooth'});
            });
            messagesContainer.addEventListener('scroll', updateJumpToLatest, {passive: true});
            window.addEventListener('resize', updateJumpToLatest, {passive: true});
        }

        function updateJumpToLatest() {
            if (!jumpButton || !messagesContainer) {
                return;
            }
            window.requestAnimationFrame(function () {
                const distanceFromBottom = messagesContainer.scrollHeight -
                    messagesContainer.scrollTop - messagesContainer.clientHeight;
                jumpButton.hidden = window.pmReviewingSearchContext !== true && distanceFromBottom < 140;
            });
        }

        function setupSendFeedback() {
            const sendButton = document.querySelector('.send-btn');
            if (!sendButton) {
                return;
            }
            sendButton.addEventListener('click', function () {
                sendButton.classList.remove('send-feedback');
                void sendButton.offsetWidth;
                sendButton.classList.add('send-feedback');
                window.setTimeout(function () {
                    sendButton.classList.remove('send-feedback');
                }, 420);
            });
        }

        function setupAccessibility() {
            document.querySelectorAll('.btn-close:not([aria-label])').forEach(function (button) {
                button.setAttribute('aria-label', 'Close');
            });

            ['userSearchResults', 'chatSearchResults'].forEach(function (id) {
                const results = document.getElementById(id);
                if (results) {
                    results.setAttribute('aria-live', 'polite');
                }
            });

            const loadingOverlay = document.getElementById('loadingOverlay');
            if (loadingOverlay) {
                loadingOverlay.setAttribute('role', 'status');
                loadingOverlay.setAttribute('aria-live', 'polite');
            }

            const interactiveObserver = new MutationObserver(function (mutations) {
                mutations.forEach(function (mutation) {
                    mutation.addedNodes.forEach(function (node) {
                        if (node.nodeType === Node.ELEMENT_NODE) {
                            enhanceInteractiveElements(node);
                        }
                    });
                });
            });
            ['userSearchResults', 'chatSearchResults'].forEach(function (id) {
                const results = document.getElementById(id);
                if (results) {
                    interactiveObserver.observe(results, {childList: true, subtree: true});
                }
            });

            document.addEventListener('focusin', function (event) {
                const item = event.target.closest && event.target.closest('.chat-item');
                if (item && item.parentElement === chatList) {
                    state.focusedChatKey = getChatKey(item);
                    syncChatListRovingTabStop(item);
                }
            });

            document.addEventListener('click', function (event) {
                const item = event.target.closest && event.target.closest('.chat-item');
                if (item && item.dataset.suppressNextClick === 'true') {
                    return;
                }
                if (item && item.parentElement === chatList) {
                    state.activeChatKey = getChatKey(item);
                }
                if (event.target.closest && event.target.closest('.mobile-chat-back')) {
                    state.focusedChatKey = state.activeChatKey || state.focusedChatKey;
                }
                const settingsItem = event.target.closest && event.target.closest('.settings-item');
                if (settingsItem && settingsItem.parentElement === settingsList) {
                    lastSettingsOpener = settingsItem;
                }
                if (window.innerWidth <= 768) {
                    scheduleMobileFocusHandoff(event, item, settingsItem);
                }
                window.setTimeout(syncCurrentStates, 0);
            }, true);

            const sidebarObserver = new MutationObserver(syncMobileNavigationAccess);
            sidebarObserver.observe(sidebar, {attributes: true, attributeFilter: ['class']});
            window.addEventListener('resize', function () {
                reconcileResponsiveSurface();
                syncMobileNavigationAccess();
            }, {passive: true});

            document.addEventListener('shown.bs.modal', function (event) {
                const focusTargets = {
                    newChatModal: 'userSearchInput',
                    chatSearchModal: 'chatSearchInput',
                    forwardModal: 'forwardSearchInput',
                    loginModal: 'loginUsername'
                };
                const targetId = focusTargets[event.target.id];
                const target = targetId ? document.getElementById(targetId) : null;
                if (target) {
                    target.focus({preventScroll: true});
                }
                event.target.querySelectorAll('.btn-close:not([aria-label])').forEach(function (button) {
                    button.setAttribute('aria-label', 'Close');
                });
            });

            syncCurrentStates();
            reconcileResponsiveSurface();
            syncMobileNavigationAccess();
        }

        function setupMessageLogAccessibility() {
            messagesList.setAttribute('role', 'log');
            messagesList.setAttribute('aria-live', 'polite');
            messagesList.setAttribute('aria-relevant', 'additions');
            messagesList.setAttribute('aria-atomic', 'false');
            if (!messagesList.hasAttribute('aria-label')) {
                messagesList.setAttribute('aria-label', 'Conversation messages');
            }
            if (messagesContainer) {
                messagesContainer.tabIndex = 0;
                messagesContainer.setAttribute('role', 'region');
                if (!messagesContainer.hasAttribute('aria-label')) {
                    messagesContainer.setAttribute('aria-label', 'Message history');
                }
            }

            const loading = document.getElementById('loadingIndicator');
            if (loading) {
                const loadingObserver = new MutationObserver(function () {
                    if (loading.classList.contains('show')) {
                        messagesList.setAttribute('aria-busy', 'true');
                        messagesList.setAttribute('aria-live', 'off');
                    } else {
                        scheduleMessageLogReady();
                    }
                });
                loadingObserver.observe(loading, {attributes: true, attributeFilter: ['class']});
            }
        }

        function beginMessageLogLoad(chatTitle) {
            window.clearTimeout(messageLogReadyTimer);
            const title = String(chatTitle || '').replace(/\s+/g, ' ').trim();
            messagesList.setAttribute('aria-label', title
                ? localized('chat.messages_in', {name: title}, 'Messages in ' + title)
                : localizedLiteral('Conversation messages'));
            messagesList.setAttribute('aria-busy', 'true');
            messagesList.setAttribute('aria-live', 'off');
            if (messagesContainer) {
                messagesContainer.setAttribute('aria-label', title
                    ? localized('chat.history_for', {name: title}, 'Message history for ' + title)
                    : localizedLiteral('Message history'));
            }
        }

        function refreshMessageLogLabels() {
            const titleElement = document.getElementById('chatTitle');
            const title = titleElement ? String(titleElement.textContent || '').replace(/\s+/g, ' ').trim() : '';
            messagesList.setAttribute('aria-label', title
                ? localized('chat.messages_in', {name: title}, 'Messages in ' + title)
                : localizedLiteral('Conversation messages'));
            if (messagesContainer) {
                messagesContainer.setAttribute('aria-label', title
                    ? localized('chat.history_for', {name: title}, 'Message history for ' + title)
                    : localizedLiteral('Message history'));
            }
            messagesList.querySelectorAll('.message-content[data-message-actions-ready="true"]').forEach(function (content) {
                content.setAttribute('aria-label', createMessageActionLabel(content));
            });
        }

        function scheduleMessageLogReady() {
            const expectedEpoch = state.chatSelectionEpoch;
            const expectedChatKey = state.activeChatKey;
            window.clearTimeout(messageLogReadyTimer);
            messageLogReadyTimer = window.setTimeout(function markMessageLogReady() {
                if (!expectedChatKey || expectedEpoch !== state.chatSelectionEpoch ||
                    expectedChatKey !== state.activeChatKey || chatContent.classList.contains('d-none')) {
                    return;
                }
                messagesList.setAttribute('aria-busy', 'false');
                messagesList.setAttribute('aria-live', 'polite');
            }, 120);
        }

        function scheduleMobileFocusHandoff(event, chatItem, settingsItem) {
            const clickedChatBack = event.target.closest && event.target.closest('.mobile-chat-back');
            const clickedSettingsBack = event.target.closest && event.target.closest('.settings-back-btn');
            window.setTimeout(function () {
                if (chatItem && chatItem.parentElement === chatList &&
                    !document.getElementById('chatContent').classList.contains('d-none')) {
                    const back = document.querySelector('.mobile-chat-back button');
                    if (back) {
                        back.focus({preventScroll: true});
                    }
                    return;
                }
                if (settingsItem && settingsItem.parentElement === settingsList && settingsContent &&
                    !settingsContent.classList.contains('d-none')) {
                    const back = settingsContent.querySelector('.settings-back-btn');
                    if (back) {
                        back.focus({preventScroll: true});
                    }
                    return;
                }
                if (clickedChatBack && !sidebar.inert) {
                    focusConversationRow(state.focusedChatKey);
                    return;
                }
                if (clickedSettingsBack && lastSettingsOpener && lastSettingsOpener.isConnected &&
                    !settingsList.classList.contains('d-none')) {
                    lastSettingsOpener.focus({preventScroll: true});
                }
            }, 80);
        }

        function reconcileResponsiveSurface() {
            if (window.innerWidth <= 768) {
                if (mainContainer.classList.contains('settings-mode')) {
                    const detailOpen = mainContainer.classList.contains('settings-detail-mode');
                    const focusWasInSidebar = sidebar.contains(document.activeElement);
                    setSurfaceVisibility(settingsList, !detailOpen);
                    setSurfaceVisibility(settingsContent, detailOpen);
                    if (detailOpen) hideMobileSidebarSurface();
                    else showMobileSidebarSurface();
                    showMobileBottomNavigation();
                    activateBottomNavigation('settings');
                    if (detailOpen && focusWasInSidebar) {
                        window.setTimeout(function focusActiveMobileSetting() {
                            const target = settingsContent && settingsContent.querySelector('.settings-back-btn, h2, h3');
                            if (target) {
                                if (!target.matches('button, a, input, select, textarea, [tabindex]')) target.tabIndex = -1;
                                target.focus({preventScroll: true});
                            }
                        }, 0);
                    }
                } else if (currentChatId !== null && !chatContent.classList.contains('d-none')) {
                    const focusWasInSidebar = sidebar.contains(document.activeElement);
                    hideMobileSidebarSurface();
                    hideMobileBottomNavigation();
                    if (focusWasInSidebar) {
                        window.setTimeout(function focusActiveMobileChat() {
                            const target = document.querySelector('.mobile-chat-back button') ||
                                document.getElementById('messageInput');
                            if (target) target.focus({preventScroll: true});
                        }, 0);
                    }
                } else {
                    showMobileSidebarSurface();
                    showMobileBottomNavigation();
                    activateBottomNavigation('chats');
                }
            } else {
                sidebar.classList.remove('show');
                sidebar.inert = false;
                sidebar.removeAttribute('aria-hidden');
                mainContainer.classList.remove('bottom-nav-hidden');
            }
        }

        function syncMobileNavigationAccess() {
            const isHiddenOffCanvas = window.innerWidth <= 768 && !sidebar.classList.contains('show');
            sidebar.inert = isHiddenOffCanvas;
            if (isHiddenOffCanvas) {
                sidebar.setAttribute('aria-hidden', 'true');
            } else {
                sidebar.removeAttribute('aria-hidden');
            }
            syncBottomNavigationAccess();
        }

        function syncCurrentStates() {
            document.querySelectorAll('.chat-item, .settings-item, .bottom-nav-item').forEach(function (item) {
                if (item.classList.contains('chat-item') && item.parentElement === chatList) {
                    const isActiveChat = item.classList.contains('active');
                    item.setAttribute('aria-selected', String(isActiveChat));
                    item.removeAttribute('aria-current');
                    if (isActiveChat) {
                        state.activeChatKey = getChatKey(item);
                    }
                    return;
                }
                if (item.classList.contains('active')) {
                    item.setAttribute('aria-current', 'page');
                } else {
                    item.removeAttribute('aria-current');
                }
            });
            syncChatListRovingTabStop();
        }

        function setupThemeControls() {
            const bodyObserver = new MutationObserver(syncThemeControls);
            bodyObserver.observe(document.body, {attributes: true, attributeFilter: ['class']});

            const menuToggle = document.getElementById('themeToggleMenu');
            if (menuToggle) {
                menuToggle.addEventListener('click', function (event) {
                    event.preventDefault();
                });
            }
            syncThemeControls();
        }

        function syncThemeControls() {
            const isLight = document.body.classList.contains('light-mode');
            document.documentElement.style.colorScheme = isLight ? 'light' : 'dark';
            localStorage.setItem('lightMode', String(isLight));

            const themeColor = document.querySelector('meta[name="theme-color"]');
            if (themeColor) {
                themeColor.content = isLight ? '#edf2f4' : '#07101c';
            }

            const quickToggle = document.getElementById('quickThemeToggle');
            if (quickToggle) {
                quickToggle.setAttribute('aria-label', isLight ? 'Switch to dark mode' : 'Switch to light mode');
                quickToggle.querySelector('i').className = isLight ? 'fas fa-sun' : 'fas fa-moon';
            }

            const menuToggle = document.getElementById('themeToggleMenu');
            const menuLabel = document.getElementById('themeToggleLabel');
            if (menuToggle) {
                const icon = menuToggle.querySelector('i');
                if (icon) {
                    icon.className = isLight ? 'fas fa-moon me-2' : 'fas fa-sun me-2';
                }
            }
            if (menuLabel) {
                menuLabel.textContent = isLight ? 'Dark Mode' : 'Light Mode';
            }
            syncVisualAppearanceControls();
        }

        window.refreshLocalizedAccessibility = function refreshLocalizedAccessibility() {
            settingsList.querySelectorAll('.settings-item').forEach(function (item) {
                const title = item.querySelector('.settings-title');
                const description = item.querySelector('.settings-description');
                const label = [title && title.textContent, description && description.textContent]
                    .filter(Boolean).join('. ');
                if (label) item.setAttribute('aria-label', label);
            });
            updateFilterButtons();
            updateSearchChrome();
            filterVisibleList();
            refreshMessageLogLabels();
            syncCurrentStates();
            syncThemeControls();
            refreshVisualChoiceLabels();
            refreshImageFailureTranslations(document);
        };
        if (window.PmI18n && window.PmI18n.ready && typeof window.PmI18n.ready.then === 'function') {
            window.PmI18n.ready.then(window.refreshLocalizedAccessibility).catch(function () {});
        }
    });
})();
