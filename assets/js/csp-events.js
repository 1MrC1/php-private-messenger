(function () {
    'use strict';

    if (window.pmSecurityHardeningReady !== true) {
        console.error('Required security hardening is unavailable; interaction handlers were not installed.');
        return;
    }

    const settingsSections = new Set([
        'profile', 'account', 'notifications', 'privacy', 'appearance', 'storage', 'about'
    ]);
    const settingKeys = new Set([
        'message_notifications', 'sound_notifications', 'desktop_notifications',
        'do_not_disturb', 'show_last_seen', 'read_receipts', 'show_profile_photo',
        'show_email', 'show_bio', 'show_phone', 'who_can_message', 'font_size',
        'chat_background', 'auto_download'
    ]);
    const fileAcceptValues = new Set([
        '.pdf,.txt,.csv,.rtf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.zip',
        'image/*', 'audio/*', 'video/*'
    ]);
    const changeActions = new Set(['toggle-2fa', 'update-setting', 'update-theme-setting']);

    const actions = Object.freeze({
        // Protected conversations: the recovery file. These call into the
        // protected interface rather than the legacy globals, and do nothing at
        // all when the encryption layer is not installed.
        'protected-recovery': function () { invoke('pmShowRecoveryDialog'); },
        'protected-recovery-download': function () { invoke('pmDownloadRecoveryFile'); },
        'protected-recovery-restore': function () { invoke('pmRestoreFromRecoveryFile'); },
        'chat-home': function () { invoke('showChatHome'); },
        'toggle-theme': function () { invoke('toggleAppTheme'); },
        'new-chat': function () { invoke('showNewChatModal'); },
        profile: function () { invoke('goToProfile'); },
        settings: function () { invoke('showSettings'); },
        logout: function () { invoke('logout'); },
        'close-settings': function () { invoke('closeSettings'); },
        'settings-root': function () { invoke('backToSettingsRoot'); },
        'back-to-chats': function () { invoke('goBackToChats'); },
        'chat-search': function () { invoke('showChatSearch'); },
        'chat-info': function () { invoke('showChatInfo'); },
        'clear-attachment': function () { invoke('clearAttachment'); },
        'attachment-options': function () { invoke('showAttachmentOptions'); },
        'send-message': function () { invoke('sendMessage'); },
        'hide-sidebar': function () { invoke('hideMobileSidebar'); },
        'back-to-login': function () { invoke('backToLogin'); },
        'chat-from-profile': function () { invoke('startChatFromProfile'); },
        'send-forwarded-message': function () { invoke('sendForwardedMessage'); },
        'reply-message': function () { invoke('replyToMessage'); },
        'copy-message': function () { invoke('copyMessage'); },
        'edit-message': function () { invoke('editMessage'); },
        'delete-message': function () { invoke('deleteMessage'); },
        'chats-tab': function () { invoke('showChatsTab'); },
        'explore-tab': function () { invoke('showExploreTab'); },
        'me-tab': function () { invoke('showMeTab'); },
        'clear-reply': function () { invoke('clearReply'); },
        'change-avatar': function () { invoke('changeAvatar'); },
        'update-profile': function () { invoke('updateProfile'); },
        'change-password': function () { invoke('changePassword'); },
        'generate-backup-codes': function () { invoke('generateBackupCodes'); },
        'delete-account': function () { invoke('deleteAccount'); },
        'clear-cache': function () { invoke('clearCache'); },
        'cancel-2fa-setup': function () { invoke('cancel2FASetup'); },
        'copy-backup-codes': function () { invoke('copyBackupCodes'); },
        'download-backup-codes': function () { invoke('downloadBackupCodes'); },
        'settings-section': function (element) {
            if (settingsSections.has(element.dataset.pmSection || '')) {
                invoke('showSettingsSection', element.dataset.pmSection);
            }
        },
        'select-file-type': function (element) {
            const accept = element.dataset.pmFileAccept || '';
            if (fileAcceptValues.has(accept)) invoke('selectFileType', accept);
        },
        'jump-to-message': function (element) {
            const id = positiveInteger(element.dataset.pmMessageId);
            if (id) invoke('jumpToMessage', id);
        },
        'image-preview': function (element) {
            if (element.dataset.pmImageSource) invoke('showImagePreview', element.dataset.pmImageSource);
        },
        'user-profile': function (element) {
            const id = positiveInteger(element.dataset.pmUserId);
            if (id) invoke('showUserProfile', id);
        },
        'verify-2fa-setup': function (element) {
            if (/^[A-Z2-7]{16,64}$/.test(element.dataset.pmSecret || '')) {
                invoke('verify2FASetup', element.dataset.pmSecret);
            }
        },
        'update-setting': function (element) {
            const key = element.dataset.pmSetting || '';
            if (!settingKeys.has(key)) return;
            invoke('updateSettings', {[key]: element.type === 'checkbox' ? element.checked : element.value});
        },
        'update-theme-setting': function (element) {
            invoke('updateSettings', {theme: element.checked ? 'dark' : 'light'});
        },
        'toggle-2fa': function (element) { invoke('toggle2FA', Boolean(element.checked)); },
        toast: function (element) {
            const keys = new Set(['about.support_soon', 'about.help_soon', 'about.legal_soon']);
            const key = element.dataset.pmToastKey || '';
            if (!keys.has(key)) return;
            const fallback = ({
                'about.support_soon': 'Support feature coming soon!',
                'about.help_soon': 'Help center coming soon!',
                'about.legal_soon': 'Terms & Privacy coming soon!'
            })[key];
            const translated = window.PmI18n && typeof window.PmI18n.t === 'function'
                ? window.PmI18n.t(key)
                : key;
            const message = translated === key ? fallback : translated;
            invoke('showToast', message, 'info');
        }
    });

    function positiveInteger(value) {
        return /^[1-9][0-9]*$/.test(value || '') && Number.isSafeInteger(Number(value))
            ? Number(value)
            : null;
    }

    function invoke(name) {
        if (typeof window[name] !== 'function') return;
        const args = Array.prototype.slice.call(arguments, 1);
        window[name].apply(window, args);
    }

    document.addEventListener('click', function (event) {
        const element = event.target.closest && event.target.closest('[data-pm-action]');
        if (!element || !actions[element.dataset.pmAction]) return;
        if (changeActions.has(element.dataset.pmAction)) return;
        if (element.matches('a[href="#"]')) event.preventDefault();
        actions[element.dataset.pmAction](element, event);
    });

    document.addEventListener('keydown', function (event) {
        if (event.defaultPrevented) return;
        const element = event.target.closest && event.target.closest('[data-pm-action][role="button"]');
        if (!element || !actions[element.dataset.pmAction] ||
            (event.key !== 'Enter' && event.key !== ' ')) {
            return;
        }
        event.preventDefault();
        element.click();
    });

    document.addEventListener('submit', function (event) {
        const form = event.target.closest && event.target.closest('[data-pm-submit]');
        if (!form) return;
        const handlers = {login: 'login', register: 'register', 'verify-2fa': 'verify2FA'};
        const handler = handlers[form.dataset.pmSubmit];
        if (!handler) return;
        event.preventDefault();
        invoke(handler, event);
    });

    document.addEventListener('input', function (event) {
        const handlers = {
            typing: 'handleTyping',
            'chat-search': 'searchInChat',
            'chat-side-search': 'searchInChat',
            'forward-search': 'searchForwardChats',
            'user-search': 'searchUsers'
        };
        const handler = handlers[event.target.dataset && event.target.dataset.pmInput];
        if (handler) invoke(handler, event.target, event);
    });

    document.addEventListener('change', function (event) {
        const type = event.target.dataset && event.target.dataset.pmChange;
        if (type === 'file-select') invoke('handleFileSelect', event);
        if (type === 'avatar-upload') invoke('handleAvatarUpload', event);
        if (event.target.dataset && actions[event.target.dataset.pmAction]) {
            actions[event.target.dataset.pmAction](event.target, event);
        }
    });

    document.addEventListener('keypress', function (event) {
        if (event.target.dataset && event.target.dataset.pmKeypress === 'message') {
            invoke('handleKeyPress', event);
        }
    });

}());
