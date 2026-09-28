


    // Messenger Complete JavaScript - All Features Included

    // Global variables
    let currentUser = null;
    let currentChatId = null;
    let currentChatInfo = null;
    let selectedUserId = null;
    let selectedMessageId = null;
    let typingTimeout = null;
    let lastTypingTime = 0;
    let typingChatId = null;
    let currentAttachment = null;
    let isLoadingMessages = false;
    let messageLoadController = null;
    let messageLoadRequestEpoch = 0;
    let messageLoadChatId = null;
    let messageLoadCursor = null;
    let newMessagePollController = null;
    let newMessagePollRequestEpoch = 0;
    let newMessagePollChatId = null;
    const newMessagePollCursors = new Map();
    let hasMoreMessages = true;
    let lastMessageId = null;
    let isInitialLoad = true;
    let userSettingsLoaded = false;
    let settingsLoadPromise = null;
    let activeSettingsSection = null;
    const settingsUpdateQueues = Object.create(null);
    let pendingSettingsUpdateCount = 0;
    let pendingClientMessage = null;
    let messageIdempotencyReady = false;
    let messageIdempotencyEpoch = 0;
    let chatListRequestEpoch = 0;
    let clientSendSemanticEpoch = 0;
    let chatSendInFlight = false;
    let chatSendUiAttempt = 0;
    let avatarSelectionEpoch = 0;
    let avatarUploadInFlight = false;
    let pendingAvatarUpload = null;
    let avatarPreviewObjectUrl = null;
    let lastStorageUsage = null;
    const MAX_SEND_ATTEMPTS = 2;
    const AUTH_REQUEST_TIMEOUT_MS = 20000;
    const CHAT_SEND_TEXT_TIMEOUT_MS = 30000;
    const CHAT_SEND_ATTACHMENT_TIMEOUT_MS = 120000;

    function translateUiText(value) {
        const text = String(value == null ? '' : value);
        return window.PmI18n && typeof window.PmI18n.translate === 'function'
            ? window.PmI18n.translate(text)
            : text;
    }

    function translateUi(key, parameters, fallback) {
        if (window.PmI18n && typeof window.PmI18n.t === 'function') {
            const translated = window.PmI18n.t(key, parameters || {});
            if (translated !== key) return translated;
        }
        return fallback === undefined ? key : fallback;
    }

    function formatUiNumber(value) {
        return window.PmI18n && typeof window.PmI18n.formatNumber === 'function'
            ? window.PmI18n.formatNumber(value)
            : String(value);
    }

    window.translatePmUiText = translateUiText;
    const CHAT_SEND_FAILURE_MESSAGES = Object.freeze({
        invalid_message: 'Messages must contain valid text and be no longer than 10,000 characters.',
        invalid_message_type: 'This message type cannot be sent here.',
        invalid_reply_target: 'The selected reply is invalid. Cancel the reply and try again.',
        invalid_client_message_id: 'Message retry protection could not be initialized. Refresh the chat and try again.',
        invalid_request: 'The message request is invalid. Check the draft and try again.',
        request_too_large: 'This message or attachment is too large and was not sent.',
        chat_access_denied: 'You no longer have access to this chat.',
        attachment_required: 'Choose an attachment before sending.',
        invalid_attachment: 'This attachment is invalid and was not sent.',
        attachment_upload_failed: 'The attachment upload was incomplete. Choose the file again and retry.',
        attachment_too_large: 'Attachments must be no larger than 50 MB.',
        unsupported_attachment_type: 'This attachment type is not supported.',
        unsafe_image: 'This image is animated or has unsupported dimensions.',
        attachment_inspection_unavailable: 'The attachment could not be inspected right now. Try again shortly.',
        attachment_changed: 'The attachment changed while it was being checked. Choose the file again.',
        attachment_rejected: 'Security scanning rejected this attachment.',
        attachment_storage_unavailable: 'Attachment storage is temporarily unavailable. Try again shortly.',
        attachment_quota_reached: 'Your 1 GB attachment storage quota has been reached.',
        attachment_hourly_limit: 'Your hourly attachment limit has been reached. Try again later.',
        attachment_attempt_limit: 'Too many attachment attempts were made. Try again later.',
        scanner_unavailable: 'Security scanning is temporarily unavailable. The attachment was not sent.',
        send_busy: 'Another message is still being processed. Keep this draft unchanged and retry shortly.',
        message_rate_limited: 'You are sending messages too quickly. Keep this draft unchanged and retry shortly.',
        reply_unavailable: 'The message you are replying to is no longer available. Cancel the reply and try again.',
        idempotency_conflict: 'This retry cannot be reused. Edit the draft to create a new send.',
        idempotency_unavailable: 'Message retry protection is temporarily unavailable. Try again shortly.',
        send_outcome_unknown: 'Delivery could not be confirmed. Check the conversation before retrying this unchanged draft.',
        messaging_unavailable: 'Delivery could not be confirmed. Check the conversation before retrying this unchanged draft.',
        request_failed: 'The message request could not be completed. Check the conversation before retrying.'
    });
    const CHAT_ATTACHMENT_MIME_TYPES = new Set([
        'image/jpeg', 'image/png', 'image/gif', 'image/webp',
        'application/pdf', 'text/plain', 'text/csv', 'application/rtf',
        'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'application/vnd.ms-excel', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'application/vnd.ms-powerpoint',
        'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'application/zip',
        'audio/mpeg', 'audio/wav', 'audio/x-wav', 'audio/ogg',
        'audio/mp4', 'audio/webm', 'audio/flac',
        'video/mp4', 'video/webm', 'video/quicktime', 'video/x-msvideo', 'video/avi'
    ]);

    window.isSupportedChatAttachment = function isSupportedChatAttachment(file) {
        const type = String(file && file.type || '').toLowerCase().split(';', 1)[0].trim();
        // Browsers sometimes omit File.type. The server's finfo inspection is
        // authoritative, so allow an unknown client hint through to validation.
        return type === '' || CHAT_ATTACHMENT_MIME_TYPES.has(type);
    };


    // Initialize app. Native equivalent of the jQuery ready() this used to
    // call: if the document has already finished parsing -- which it has, since
    // this script is loaded at the end of the body -- run immediately rather
    // than waiting for an event that has already fired.
    function whenDocumentReady(start) {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', start, {once: true});
        } else {
            start();
        }
    }

    whenDocumentReady(function () {
        if (window.pmSecurityHardeningReady !== true) {
            console.error('Required security hardening did not initialize; application startup was blocked.');
            document.documentElement.setAttribute('data-pm-security-blocked', 'true');
            return;
        }
        // No need to read from localStorage anymore
        validateSession();

        // Auto-refresh chats and messages
        setInterval(refreshChats, 5000);
        setInterval(function () {
            if (currentChatId && !isLoadingMessages) {
                checkForNewMessages();
            }
        }, 2000);

        // Initialize features
        initializeFeatures();
    });

    // Initialize features
    function initializeFeatures() {
        // Initialize night mode from storage
        const isLightMode = localStorage.getItem('lightMode') === 'true';
        if (isLightMode) {
            document.body.classList.add('light-mode');
            const nightBtn = document.querySelector('.fa-moon');
            if (nightBtn) {
                nightBtn.className = 'fas fa-sun';
            }
        }

        // Auto-resize textarea
        const messageInput = document.getElementById('messageInput');
        if (messageInput) {
            messageInput.addEventListener('input', function () {
                this.style.height = 'auto';
                this.style.height = Math.min(this.scrollHeight, 120) + 'px';
                cancelPendingClientMessageIfComposerChanged();
            });
        }

        // Update status more frequently
        setInterval(updateOnlineStatus, 30000); // Every 30 seconds
    }

    function showLoginModal() {
        new bootstrap.Modal(document.getElementById('loginModal')).show();
    }

    function fetchWithTimeout(resource, options, timeoutMs, responseHandler) {
        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        const requestOptions = Object.assign({}, options || {});
        if (controller) requestOptions.signal = controller.signal;
        let timeoutId = null;
        const timeoutPromise = new Promise(function (_resolve, reject) {
            timeoutId = window.setTimeout(function () {
                if (controller) controller.abort();
                const error = new Error('The request timed out');
                error.name = 'TimeoutError';
                reject(error);
            }, timeoutMs);
        });
        const request = fetch(resource, requestOptions).then(function (response) {
            return typeof responseHandler === 'function' ? responseHandler(response) : response;
        });
        return Promise.race([request, timeoutPromise]).finally(function () {
            if (timeoutId !== null) window.clearTimeout(timeoutId);
        });
    }

    function login(event) {
        event.preventDefault();

        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value;

        if (!username || !password) {
            showToast('Please enter both username and password', 'error');
            return;
        }

        setButtonLoading('loginSubmitBtn', true);

        fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'login',
                username: username,
                password: password
            })
        }, AUTH_REQUEST_TIMEOUT_MS, function (response) {
            return response.json();
        })
            .then(data => {
                document.getElementById('loginPassword').value = '';
                if (data.success) {
                    // Normal login (no 2FA)
                    currentUser = data.user;
                    bootstrap.Modal.getInstance(document.getElementById('loginModal')).hide();
                    showToast('Welcome back, ' + currentUser.first_name + '!', 'success');
                    initializeApp();
                } else if (data.requires_2fa) {
                    // 2FA required - the session is handled server-side
                    show2FAVerification();
                    showToast('Please enter your 2FA code to complete login', 'info');
                } else {
                    showToast(data.message || 'Login failed. Please check your credentials.', 'error');
                }
            })
            .catch(error => {
                document.getElementById('loginPassword').value = '';
                console.error('Login error:', error);
                showToast('Login failed. Please check your connection and try again.', 'error');
            })
            .finally(() => {
                setButtonLoading('loginSubmitBtn', false);
            });
    }

    // Show 2FA Verification
    function show2FAVerification() {
        document.getElementById('loginRegisterTabs').classList.add('d-none');
        document.getElementById('twoFactorVerification').classList.remove('d-none');

        // Focus on 2FA input
        setTimeout(() => {
            document.getElementById('twoFactorCode').focus();
        }, 300);
    }

    function backToLogin() {
        document.getElementById('twoFactorVerification').classList.add('d-none');
        document.getElementById('loginRegisterTabs').classList.remove('d-none');

        // Clear 2FA data
        document.getElementById('loginPassword').value = '';
        document.getElementById('twoFactorCode').value = '';
    }

    function verify2FA(event) {
        event.preventDefault();

        const code = document.getElementById('twoFactorCode').value.trim();

        if (!code || (code.length !== 6 && code.length !== 8)) {
            showToast('Please enter a valid 6-digit code or 8-character backup code', 'error');
            return;
        }

        setButtonLoading('verify2FABtn', true);

        fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'verify_2fa_login',
                code: code // Remove user_id - let server get it from session
            })
        }, AUTH_REQUEST_TIMEOUT_MS, function (response) {
            return response.json();
        })
            .then(data => {
                if (data.success) {
                    // 2FA verified successfully, now complete the login
                    return completeLoginAfter2FA();
                } else {
                    showToast(data.message || 'Invalid verification code. Please try again.', 'error');
                    document.getElementById('twoFactorCode').value = '';
                    document.getElementById('twoFactorCode').focus();
                }
            })
            .catch(error => {
                document.getElementById('twoFactorCode').value = '';
                console.error('2FA verification error:', error);
                showToast('Verification failed. Please try again.', 'error');
            })
            .finally(() => {
                setButtonLoading('verify2FABtn', false);
            });
    }

    // New function to complete login after 2FA
    function completeLoginAfter2FA() {
        return fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'complete_2fa_login'
                // No user_id needed - server gets it from session
            })
        }, AUTH_REQUEST_TIMEOUT_MS, function (response) {
            return response.json();
        })
            .then(data => {
                if (data.success) {
                    currentUser = data.user;
                    bootstrap.Modal.getInstance(document.getElementById('loginModal')).hide();
                    showToast('Login successful! Welcome back, ' + currentUser.first_name + '!', 'success');
                    initializeApp();

                    // Clear 2FA data
                    document.getElementById('loginPassword').value = '';
                    document.getElementById('twoFactorCode').value = '';
                } else {
                    showToast(data.message || 'Login completion failed. Please try again.', 'error');
                    backToLogin();
                }
            })
            .catch(error => {
                console.error('Complete login error:', error);
                showToast('Login completion failed. Please try again.', 'error');
                backToLogin();
            });
    }

    function register(event) {
        event.preventDefault();

        const formData = {
            action: 'register',
            username: document.getElementById('registerUsername').value.trim(),
            email: document.getElementById('registerEmail').value.trim(),
            password: document.getElementById('registerPassword').value,
            first_name: document.getElementById('registerFirstName').value.trim(),
            last_name: document.getElementById('registerLastName').value.trim()
        };

        // Validation
        if (!formData.username || !formData.email || !formData.password || !formData.first_name || !formData.last_name) {
            showToast('Please fill in all required fields', 'error');
            return;
        }

        if (formData.username.length < 3) {
            showToast('Username must be at least 3 characters long', 'error');
            return;
        }

        if (formData.password.length < 12 || formData.password.length > 72) {
            showToast('Password must be between 12 and 72 characters long', 'error');
            return;
        }

        setButtonLoading('registerSubmitBtn', true);

        fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(formData)
        }, AUTH_REQUEST_TIMEOUT_MS, function (response) {
            return response.json();
        })
            .then(data => {
                if (data.success) {
                    showToast('Registration successful! Please login with your new account.', 'success');
                    document.getElementById('login-tab').click();
                    document.getElementById('registerForm').reset();
                } else {
                    showToast(data.message || 'Registration failed. Please try again.', 'error');
                }
            })
            .catch(error => {
                console.error('Registration error:', error);
                showToast('Registration failed. Please check your connection and try again.', 'error');
            })
            .finally(() => {
                setButtonLoading('registerSubmitBtn', false);
            });
    }

    function validateSession() {
        fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include', // Important for cookies
            body: JSON.stringify({
                action: 'validate'
            })
        }, AUTH_REQUEST_TIMEOUT_MS, function (response) {
            return response.json();
        })
            .then(data => {
                if (data.success) {
                    currentUser = data.user;
                    initializeApp();
                } else {
                    showLoginModal();
                }
            })
            .catch(error => {
                console.error('Session validation error:', error);
                showLoginModal();
            });
    }

    async function logout() {
        const confirmed = await showConfirmDialog(
            'Logout',
            'Are you sure you want to logout?',
            'Logout',
            'warning'
        );

        if (!confirmed) return;

        fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'logout'
            })
        }, AUTH_REQUEST_TIMEOUT_MS)
            .then(() => {
                showToast('You have been logged out successfully', 'success', 2000);
                setTimeout(() => {
                    location.reload();
                }, 2000);
            })
            .catch(error => {
                console.error('Logout error:', error);
                showToast('Logout failed. Refreshing page...', 'warning');
                setTimeout(() => {
                    location.reload();
                }, 2000);
            });
    }


    function initializeApp() {
        try {
            updateUserInfo();
            loadChats();
            initializeChatFeatures();
            setupContextMenuListeners();
            loadUserSettings();

            // Show sidebar by default on mobile, welcome screen on desktop
            if (window.innerWidth <= 768) {
                // Mobile: show sidebar with chat list and bottom nav (no overlay)
                document.getElementById('sidebar').classList.add('show');
                document.getElementById('sidebarOverlay').classList.remove('show');
                document.body.style.overflow = '';
                showBottomNav();
                updateBottomNavActive('chats');
                // Hide welcome screen and chat content initially
                document.getElementById('welcomeScreen').classList.add('d-none');
                document.getElementById('chatContent').classList.add('d-none');
            } else {
                // Desktop: show welcome screen
                document.getElementById('welcomeScreen').classList.remove('d-none');
                document.getElementById('chatContent').classList.add('d-none');
            }

            // Show welcome message
            showToast('Welcome to Messenger! 🎉', 'success', 3000);
        } catch (error) {
            console.error('App initialization error:', error);
            showToast('Some features may not work properly. Please refresh the page.', 'warning', 5000);
        }
    }

    function setupContextMenuListeners() {
        // Hide context menu on escape key
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                hideContextMenu();
            }
        });

        // Hide context menu on scroll
        document.getElementById('messagesContainer').addEventListener('scroll', hideContextMenu);
    }

    function updateUserInfo() {
        document.getElementById('userName').textContent = currentUser.first_name + ' ' + currentUser.last_name;

        // Fix the color by setting inline style
        const userStatus = document.getElementById('userStatus');
        userStatus.textContent = '@' + currentUser.username;
        userStatus.style.color = '#adb5bd'; // var(--text-secondary) value

        // Update avatar with proper handling
        const userAvatarEl = document.getElementById('userAvatar');
        if (currentUser.avatar) {
            userAvatarEl.innerHTML = '<img src="' + currentUser.avatar + '" alt="Avatar" class="avatar-image-fill">';
        } else {
            userAvatarEl.innerHTML = currentUser.first_name.charAt(0).toUpperCase();
        }
    }

    // Chat functions
    function loadChats() {
        const requestEpoch = ++chatListRequestEpoch;
        return fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'get_chats'
            })
            })
            .then(function (response) {
                return response.json().then(function (data) {
                    return {response: response, data: data};
                });
            })
            .then(function (result) {
                // Polls can overlap on a slow network. Only the newest request
                // may change the fleet capability or replace the visible list.
                if (requestEpoch !== chatListRequestEpoch) return false;

                const data = result.data;
                const isValidSuccess = result.response.ok && data && data.success === true &&
                    Array.isArray(data.chats);
                // Missing capability data is not proof that a legacy/rolled-back
                // node understands client_message_id. Fail closed on every
                // latest response that is not an explicit, valid readiness true.
                setMessageIdempotencyCapability(
                    isValidSuccess && data.message_idempotency_ready === true
                );
                if (isValidSuccess) {
                    renderChats(data.chats);
                    return true;
                }
                return false;
            })
            .catch(function (error) {
                if (requestEpoch === chatListRequestEpoch) {
                    setMessageIdempotencyCapability(false);
                }
                console.error('Load chats error:', error);
                return false;
            });
    }

    function renderChats(chats) {
        const chatList = document.getElementById('chatList');
        chatList.innerHTML = '';

// If no chats, show empty state only on mobile
        if (chats.length === 0) {
            // Only show empty state on mobile
            if (window.innerWidth <= 768) {
                const emptyDiv = document.createElement('div');
                emptyDiv.className = 'empty-chat-list';
                emptyDiv.innerHTML = `
            <div class="empty-icon">
                <i class="fas fa-comments"></i>
            </div>
            <h4>No Chats Yet</h4>
            <p>Start connecting with friends and colleagues</p>
            <button class="btn btn-primary" data-pm-action="new-chat">
                <i class="fas fa-plus me-2"></i>Start New Chat
            </button>
        `;
                chatList.appendChild(emptyDiv);
            }
            return;
        }
        chats.forEach(function (chat) {
            const chatItem = document.createElement('div');
            chatItem.className = 'chat-item';
            chatItem.onclick = function () {
                selectChat(chat.chat_id, chat);
            };

            const avatar = chat.chat_avatar ?
                '<img src="' + chat.chat_avatar + '" alt="Avatar" class="avatar-image-fill">' :
                (chat.title ? chat.title.charAt(0).toUpperCase() : 'C');

            const unreadBadge = chat.unread_count > 0 ?
                '<div class="unread-count">' + chat.unread_count + '</div>' : '';

            const lastMessageTime = chat.last_message_time ?
                formatTime(chat.last_message_time) : '';
            const chatTitle = chat.title !== null && chat.title !== undefined && String(chat.title) !== ''
                ? chat.title
                : translateUi('common.unknown', {}, 'Unknown');
            const lastMessage = chat.last_message !== null && chat.last_message !== undefined &&
                String(chat.last_message) !== ''
                ? chat.last_message
                : translateUi('chat.no_messages', {}, 'No messages yet');

            chatItem.innerHTML =
                '<div class="chat-avatar">' + avatar + '</div>' +
                '<div class="chat-info">' +
                '<div class="chat-name">' + chatTitle + '</div>' +
                '<div class="chat-last-message">' + lastMessage + '</div>' +
                '</div>' +
                '<div class="chat-meta">' +
                '<div>' + lastMessageTime + '</div>' +
                unreadBadge +
                '</div>';

            chatList.appendChild(chatItem);
        });
    }


    function loadMessages(chatId, beforeMessageId, isNewMessage) {
        beforeMessageId = beforeMessageId || null;
        isNewMessage = isNewMessage || false;

        const requestChatId = String(chatId);
        if (!beforeMessageId) {
            if (typeof window.cancelNewMessagePoll === 'function') window.cancelNewMessagePoll();
            newMessagePollCursors.delete(requestChatId);
        }
        if (isLoadingMessages && messageLoadChatId === requestChatId) {
            const activeIsPagination = messageLoadCursor !== null;
            const requestedIsPagination = beforeMessageId !== null;
            if (!activeIsPagination || requestedIsPagination) return;
        }
        if (messageLoadController) messageLoadController.abort();
        const requestEpoch = ++messageLoadRequestEpoch;
        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        messageLoadController = controller;
        messageLoadChatId = requestChatId;
        messageLoadCursor = beforeMessageId;
        isLoadingMessages = true;

        // Show loading indicator only for initial load or scroll load
        if (!isNewMessage) {
            document.getElementById('loadingIndicator').classList.add('show');
        }

        const requestData = {
            action: 'get_messages',
            chat_id: chatId,
            limit: 30
        };

        if (beforeMessageId) {
            requestData.before_message_id = beforeMessageId;
        }

        const timeoutId = window.setTimeout(function () {
            if (requestEpoch === messageLoadRequestEpoch && controller) controller.abort();
        }, 20000);

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            signal: controller ? controller.signal : undefined,
            body: JSON.stringify(requestData)
        })
            .then(response => response.json())
            .then(data => {
                if (requestEpoch !== messageLoadRequestEpoch || String(currentChatId) !== requestChatId) return;
                if (data.success) {
                    renderMessages(data.messages, beforeMessageId !== null, isNewMessage);
                    hasMoreMessages = data.messages.length === 30;

                    if (!beforeMessageId) {
                        const newestMessage = data.messages.length
                            ? data.messages[data.messages.length - 1]
                            : null;
                        const newestId = newestMessage ? Number(newestMessage.id) : 0;
                        newMessagePollCursors.set(
                            requestChatId,
                            Number.isSafeInteger(newestId) && newestId > 0 ? newestId : null
                        );
                    }

                    // Update lastMessageId for pagination
                    if (data.messages.length > 0 && !beforeMessageId) {
                        lastMessageId = data.messages[0].id;
                    }

                    // Refresh read status after a short delay to show updates
                    if (!isNewMessage && !beforeMessageId) {
                        setTimeout(() => {
                            refreshMessageReadStatus(chatId);
                        }, 500);
                    }
                }
            })
            .catch(function (error) {
                if (!error || error.name !== 'AbortError') console.error('Load messages error:', error);
            })
            .finally(function () {
                window.clearTimeout(timeoutId);
                if (requestEpoch !== messageLoadRequestEpoch) return;
                isLoadingMessages = false;
                messageLoadController = null;
                messageLoadChatId = null;
                messageLoadCursor = null;
                document.getElementById('loadingIndicator').classList.remove('show');
                isInitialLoad = false;
            });
    }

    window.cancelActiveMessageLoad = function cancelActiveMessageLoad() {
        messageLoadRequestEpoch += 1;
        if (messageLoadController) messageLoadController.abort();
        messageLoadController = null;
        messageLoadChatId = null;
        messageLoadCursor = null;
        isLoadingMessages = false;
        isInitialLoad = false;
        const loading = document.getElementById('loadingIndicator');
        if (loading) loading.classList.remove('show');
    };

    function refreshMessageReadStatus(chatId) {
        if (!chatId || isLoadingMessages) return;
        const requestChatId = String(chatId);

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'get_messages',
                chat_id: chatId,
                limit: 50
            })
        })
            .then(response => response.json())
            .then(data => {
                if (String(currentChatId) !== requestChatId) return;
                if (data.success) {
                    // Update only the read status of existing messages
                    data.messages.forEach(message => {
                        const existingMessage = document.querySelector('#messagesList [data-message-id="' + message.id + '"]');
                        if (existingMessage && message.sender_id == currentUser.id) {
                            const statusElement = existingMessage.querySelector('.message-status');
                            if (statusElement) {
                                const readCount = Number(message.read_count) || 0;
                                if (readCount > 0) {
                                    statusElement.innerHTML = '<i class="fas fa-check-double"></i>';
                                    statusElement.className = 'message-status status-read';
                                } else if (!statusElement.classList.contains('status-read')) {
                                    statusElement.innerHTML = '<i class="fas fa-check"></i>';
                                    statusElement.className = 'message-status status-delivered';
                                }
                            }
                        }
                    });
                }
            })
            .catch(error => console.debug('Refresh read status error:', error));
    }

function renderMessages(messages, isPrepend, isNewMessage) {
    isPrepend = isPrepend || false;
    isNewMessage = isNewMessage || false;

    const container = document.getElementById('messagesList');
    const scrollContainer = document.getElementById('messagesContainer');

    // Remember scroll position for prepending
    let oldScrollHeight = 0;
    if (isPrepend) {
        oldScrollHeight = scrollContainer.scrollHeight;
    }

    // Check if user was at bottom before adding messages
    const wasAtBottom = scrollContainer.scrollTop + scrollContainer.clientHeight >= scrollContainer.scrollHeight - 50;

    // For new messages, check for duplicates
    if (isNewMessage) {
        const existingMessageIds = new Set();
        container.querySelectorAll('[data-message-id]').forEach(msg => {
            existingMessageIds.add(msg.dataset.messageId);
        });

        // Filter out messages that already exist
        messages = messages.filter(msg => !existingMessageIds.has(msg.id.toString()));
        
        // If no new messages after filtering, return
        if (messages.length === 0) {
            return;
        }
    }

    if (!isPrepend && !isNewMessage) {
        container.innerHTML = '';
    }

    messages.forEach(function (message, index) {
        // Check if message already exists (additional safety check)
        if (container.querySelector('[data-message-id="' + message.id + '"]')) {
            return; // Skip if message already exists
        }

        const messageDiv = document.createElement('div');
        messageDiv.className = 'message ' + (message.sender_id == currentUser.id ? 'outgoing' : 'incoming');
        messageDiv.dataset.messageId = message.id;

        // Only add animation for truly new messages
        if (isNewMessage && index === messages.length - 1) {
            messageDiv.classList.add('new-message');
        }

        const senderAvatar = message.avatar ?
            '<img src="' + message.avatar + '" alt="Avatar" class="message-avatar-image">' :
            '<div class="message-avatar-fallback">' + message.first_name.charAt(0) + '</div>';

        let content = '';
        let replyContent = '';

        // Handle reply
        if (message.reply_to_message_id && message.reply_content) {
            const replySender = message.reply_sender_name || 'User';
            replyContent = '<div class="reply-to" data-pm-action="jump-to-message" data-pm-message-id="' +
                Number(message.reply_to_message_id) + '">' +
                '<div class="reply-sender">' + replySender + '</div>' +
                '<div class="reply-content">' + escapeHtml(message.reply_content.substring(0, 100)) + (message.reply_content.length > 100 ? '...' : '') + '</div>' +
                '</div>';
        }

        if (message.message_type === 'text') {
            content = escapeHtml(message.content);
        } else if (message.message_type === 'image') {
            content = '<div class="image-message">' +
                '<img src="' + message.file_path + '" alt="' + message.file_name + '" data-pm-action="image-preview" data-pm-image-source="' +
                escapeHtml(message.file_path) + '">' +
                '</div>';
            // Add caption if it exists and is not just the filename
            if (message.content && message.content !== message.file_name) {
                content += '<div class="message-caption">' + escapeHtml(message.content) + '</div>';
            }
        } else {
            const fileIcon = getFileIcon(message.file_name);
            const fileSize = formatFileSize(message.file_size);
            content = '<div class="file-message">' +
                '<div class="file-icon">' +
                '<i class="fas ' + fileIcon.icon + '"></i>' +
                '</div>' +
                '<div class="file-info">' +
                '<div class="file-name">' + message.file_name + '</div>' +
                '<div class="file-size">' + fileSize + '</div>' +
                '</div>' +
                '<a href="' + message.file_path + '" class="btn btn-sm btn-link text-white">' +
                '<i class="fas fa-download"></i>' +
                '</a>' +
                '</div>';
            // Add caption if it exists and is not just the filename
            if (message.content && message.content !== message.file_name) {
                content += '<div class="message-caption">' + escapeHtml(message.content) + '</div>';
            }
        }

        let messageContent = replyContent + content + '<div class="message-time">' + formatTime(message.created_at) + '</div>';

        // ONLY add status for sender's own messages
        if (message.sender_id == currentUser.id) {
            messageContent += getMessageStatus(message);
        }

        messageDiv.innerHTML =
            (message.sender_id != currentUser.id ? '<div class="sender-avatar sender-avatar-action" data-pm-action="user-profile" data-pm-user-id="' +
                Number(message.sender_id) + '">' + senderAvatar + '</div>' : '') +
            '<div class="message-content">' + messageContent + '</div>' +
            (message.sender_id == currentUser.id ? '<div class="sender-avatar">' + senderAvatar + '</div>' : '');

        // Add context menu
        messageDiv.querySelector('.message-content').addEventListener('contextmenu', function (event) {
            event.preventDefault();
            showMessageContextMenu(event, message.id);
        });

        if (isPrepend) {
            container.insertBefore(messageDiv, container.firstChild);
        } else {
            container.appendChild(messageDiv);
        }
    });

    // Handle scrolling
    if (isPrepend) {
        // Maintain scroll position when prepending
        const newScrollHeight = scrollContainer.scrollHeight;
        scrollContainer.scrollTop = newScrollHeight - oldScrollHeight;
    } else if (wasAtBottom || isInitialLoad || isNewMessage) {
        // Scroll to bottom for new messages or initial load
        setTimeout(function () {
            scrollContainer.scrollTop = scrollContainer.scrollHeight;
        }, 50);
    }
}

    // Message status and context menu functions
    function getMessageStatus(message) {
        let statusIcon = '';
        let statusClass = '';

        // Check read status - convert to numbers to be sure
        const readCount = Number(message.read_count) || 0;

        if (readCount > 0) {
            // Message has been read by recipient (two ticks, blue)
            statusIcon = '<i class="fas fa-check-double"></i>';
            statusClass = 'status-read';
        } else {
            // Message delivered but not read (one tick, gray)
            statusIcon = '<i class="fas fa-check"></i>';
            statusClass = 'status-delivered';
        }

        return '<div class="message-status ' + statusClass + '">' + statusIcon + '</div>';
    }

    function showMessageContextMenu(event, messageId) {
        event.preventDefault();
        event.stopPropagation();

        selectedMessageId = messageId;

        const contextMenu = document.getElementById('contextMenu');
        const message = document.querySelector('[data-message-id="' + messageId + '"]');
        const isOwnMessage = message && message.classList.contains('outgoing');
        const isEditableText = isOwnMessage && message.dataset.messageType === 'text';

        // Show/hide edit and delete options for own messages
        const editOption = document.getElementById('editOption');
        const deleteOption = document.getElementById('deleteOption');
        if (editOption) editOption.style.display = isEditableText ? 'block' : 'none';
        if (deleteOption) deleteOption.style.display = isOwnMessage ? 'block' : 'none';

        // Position the context menu
        contextMenu.style.display = 'block';
        contextMenu.style.left = event.pageX + 'px';
        contextMenu.style.top = event.pageY + 'px';

        // Adjust if menu goes off screen
        setTimeout(() => {
            const rect = contextMenu.getBoundingClientRect();
            if (rect.right > window.innerWidth) {
                contextMenu.style.left = (event.pageX - rect.width) + 'px';
            }
            if (rect.bottom > window.innerHeight) {
                contextMenu.style.top = (event.pageY - rect.height) + 'px';
            }
        }, 10);

        // Close menu when clicking elsewhere
        setTimeout(() => {
            document.addEventListener('click', hideContextMenu, {once: true});
            document.addEventListener('scroll', hideContextMenu, {once: true});
        }, 50);
    }

    function hideContextMenu() {
        document.getElementById('contextMenu').style.display = 'none';
    }

    function getRenderedMessageBody(messageElement) {
        if (!messageElement) return '';
        const body = messageElement.querySelector('.message-text');
        if (body) return body.textContent;
        const caption = messageElement.querySelector('.message-caption');
        if (caption) return caption.textContent;
        const fileName = messageElement.querySelector('.file-name');
        if (fileName) return fileName.textContent;
        const image = messageElement.querySelector('.image-message img');
        return image ? (image.getAttribute('alt') || 'Image') : '';
    }

    function copyMessage() {
        hideContextMenu();
        if (!selectedMessageId) return;

        const messageElement = document.querySelector('[data-message-id="' + selectedMessageId + '"]');
        if (messageElement) {
            const text = getRenderedMessageBody(messageElement);

            navigator.clipboard.writeText(text).then(function () {
                showToast('Message copied to clipboard');
            }).catch(function () {
                const textarea = document.createElement('textarea');
                textarea.value = text;
                document.body.appendChild(textarea);
                textarea.select();
                document.execCommand('copy');
                document.body.removeChild(textarea);
                showToast('Message copied to clipboard');
            });
        }
    }

    function forwardMessage() {
        hideContextMenu();
        showToast('Forward feature coming soon!');
    }

    function editMessage() {
        hideContextMenu();
        if (!selectedMessageId) return;

        const messageElement = document.querySelector('[data-message-id="' + selectedMessageId + '"]');
        if (messageElement) {
            const text = getRenderedMessageBody(messageElement);

            const input = document.getElementById('messageInput');
            input.value = text;
            input.placeholder = 'Edit message...';
            input.focus();
            input.dataset.editMessageId = selectedMessageId;
            input.dispatchEvent(new Event('input', {bubbles: true}));
        }
    }

    async function deleteMessage() {
        hideContextMenu();
        if (!selectedMessageId) return;
        const messageIdToDelete = selectedMessageId;

        const confirmed = await showConfirmDialog(
            'Delete Message',
            'Are you sure you want to delete this message? This action cannot be undone.',
            'Delete',
            'danger'
        );

        if (!confirmed) return;

        showToast('Deleting message...', 'info');

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'delete_message',
                message_id: messageIdToDelete
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    const messageElement = document.querySelector('[data-message-id="' + messageIdToDelete + '"]');
                    if (messageElement) {
                        messageElement.style.opacity = '0.5';
                        messageElement.querySelector('.message-content').innerHTML = '<em><i class="fas fa-trash me-1"></i>This message was deleted</em>';
                    }
                    showToast('Message deleted successfully', 'success');
                } else {
                    showToast(data.message || 'Failed to delete message', 'error');
                }
            })
            .catch(error => {
                console.error('Delete message error:', error);
                showToast('Failed to delete message. Please try again.', 'error');
            });
    }

    function replyToMessage() {
        hideContextMenu();
        if (!selectedMessageId) return;

        const messageElement = document.querySelector('[data-message-id="' + selectedMessageId + '"]');
        if (messageElement) {
            const text = getRenderedMessageBody(messageElement);

            // Get sender info
            const sender = getReplySender(messageElement);

            const input = document.getElementById('messageInput');

            // Create reply preview
            markClientSendSemanticsChanged();
            showReplyPreview(selectedMessageId, sender.name, text, sender.kind);

            setReplyComposerSender(input, sender.kind, sender.name);
            input.focus();
            input.dataset.replyTo = selectedMessageId;

            showToast('💬 Replying to message');
        }
    }

    function getReplySender(messageElement) {
        if (messageElement && messageElement.classList.contains('outgoing')) {
            return {kind: 'self', name: ''};
        }
        const rawName = currentChatInfo && currentChatInfo.other_user
            ? String(currentChatInfo.other_user.first_name || '').trim()
            : '';
        return rawName
            ? {kind: 'name', name: rawName}
            : {kind: 'fallback', name: ''};
    }

    function replySenderDisplayName(senderKind, senderName) {
        if (senderKind === 'self') return translateUi('common.you', {}, 'You');
        if (senderKind === 'fallback') return translateUi('common.user', {}, 'User');
        return String(senderName || '');
    }

    function setReplyComposerSender(input, senderKind, senderName) {
        if (!input) return;
        const kind = ['self', 'fallback', 'name'].includes(senderKind)
            ? senderKind
            : (senderName ? 'name' : 'fallback');
        const rawName = kind === 'name' ? String(senderName || '') : '';
        const displayName = replySenderDisplayName(kind, rawName);
        input.dataset.replySenderKind = kind;
        if (kind === 'name') input.dataset.replySenderName = rawName;
        else delete input.dataset.replySenderName;
        input.placeholder = translateUi(
            'chat.reply_to',
            {name: displayName},
            'Reply to ' + displayName + '...'
        );
    }

    function refreshReplyComposerSender() {
        const input = document.getElementById('messageInput');
        if (!input || !input.dataset.replyTo || !input.dataset.replySenderKind) return;
        setReplyComposerSender(input, input.dataset.replySenderKind, input.dataset.replySenderName || '');
    }

    function showReplyPreview(messageId, senderName, content, senderKind) {
        // Remove existing reply preview
        const existingPreview = document.querySelector('.reply-preview');
        if (existingPreview) {
            existingPreview.remove();
        }

        // Create reply preview
        const kind = ['self', 'fallback', 'name'].includes(senderKind)
            ? senderKind
            : (senderName ? 'name' : 'fallback');
        const displayName = replySenderDisplayName(kind, kind === 'name' ? senderName : '');
        const replyLabel = translateUi(
            'chat.replying_to',
            {name: displayName},
            'Replying to ' + displayName
        );
        const replyPreview = document.createElement('div');
        replyPreview.className = 'reply-preview';
        replyPreview.innerHTML =
            '<div class="reply-close" data-pm-action="clear-reply" role="button" tabindex="0">&times;</div>' +
            '<div class="reply-sender">' + escapeHtml(replyLabel) + '</div>' +
            '<div class="reply-content">' + escapeHtml(content.substring(0, 100)) + (content.length > 100 ? '...' : '') + '</div>';

        // Insert before message input
        const inputContainer = document.querySelector('.message-input-container');
        inputContainer.insertBefore(replyPreview, inputContainer.firstChild);
    }

    function clearReply() {
        markClientSendSemanticsChanged();
        const replyPreview = document.querySelector('.reply-preview');
        if (replyPreview) {
            replyPreview.remove();
        }

        const input = document.getElementById('messageInput');
        input.placeholder = translateUi('chat.type_message', {}, 'Type a message...');
        delete input.dataset.replyTo;
        delete input.dataset.replySenderKind;
        delete input.dataset.replySenderName;
    }

    // Setup scroll event listener for infinite scroll
    function setupInfiniteScroll() {
        const scrollContainer = document.getElementById('messagesContainer');

        function handleScroll() {
            // Only load more messages when scrolled to top
            if (scrollContainer.scrollTop < 100 && hasMoreMessages && !isLoadingMessages) {
                const firstMessage = document.querySelector('#messagesList [data-message-id]');
                if (firstMessage) {
                    const firstMessageId = firstMessage.dataset.messageId;
                    loadMessages(currentChatId, firstMessageId);
                }
            }
        }

        scrollContainer.addEventListener('scroll', handleScroll);
        // Store reference for temporary removal
        scrollContainer.onscroll = handleScroll;
    }

    function createClientMessageId() {
        const secureCrypto = window.crypto;
        if (!secureCrypto || typeof secureCrypto.getRandomValues !== 'function') {
            throw new Error('Secure message identifiers are unavailable in this browser');
        }
        if (typeof secureCrypto.randomUUID === 'function') {
            return secureCrypto.randomUUID().toLowerCase();
        }

        const bytes = new Uint8Array(16);
        secureCrypto.getRandomValues(bytes);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        const hex = Array.from(bytes, function (value) {
            return value.toString(16).padStart(2, '0');
        }).join('');
        return hex.slice(0, 8) + '-' + hex.slice(8, 12) + '-' + hex.slice(12, 16) + '-' +
            hex.slice(16, 20) + '-' + hex.slice(20);
    }

    function clientMessageSemanticsMatch(kind, chatId, content, replyToId, attachment) {
        return pendingClientMessage !== null &&
            pendingClientMessage.kind === kind &&
            pendingClientMessage.chatId === String(chatId) &&
            pendingClientMessage.content === content &&
            pendingClientMessage.replyToId === (replyToId ? String(replyToId) : '') &&
            pendingClientMessage.attachment === (attachment || null);
    }

    function clientMessageIdFor(kind, chatId, content, replyToId, attachment) {
        if (clientMessageSemanticsMatch(kind, chatId, content, replyToId, attachment)) {
            return pendingClientMessage.id;
        }

        pendingClientMessage = {
            id: createClientMessageId(),
            kind: kind,
            chatId: String(chatId),
            content: content,
            replyToId: replyToId ? String(replyToId) : '',
            attachment: attachment || null
        };
        return pendingClientMessage.id;
    }

    function clearPendingClientMessage(expectedId) {
        if (!expectedId || (pendingClientMessage && pendingClientMessage.id === expectedId)) {
            pendingClientMessage = null;
        }
    }

    function markClientSendSemanticsChanged() {
        clientSendSemanticEpoch += 1;
        clearPendingClientMessage();
    }

    function setMessageIdempotencyCapability(isReady) {
        const nextValue = isReady === true;
        if (nextValue !== messageIdempotencyReady) {
            messageIdempotencyReady = nextValue;
            messageIdempotencyEpoch += 1;
        }
        if (!messageIdempotencyReady) clearPendingClientMessage();
    }

    function cancelPendingClientMessageIfComposerChanged() {
        // This function is the message input's semantic-change hook. Advance
        // the epoch even in legacy mode, where no pending UUID exists.
        clientSendSemanticEpoch += 1;
        if (!pendingClientMessage) return;
        const input = document.getElementById('messageInput');
        if (!input) {
            clearPendingClientMessage();
            return;
        }
        const attachment = currentAttachment || null;
        const kind = attachment ? 'attachment' : 'text';
        if (!clientMessageSemanticsMatch(
            kind,
            currentChatId,
            input.value.trim(),
            input.dataset.replyTo,
            attachment
        )) {
            clearPendingClientMessage();
        }
    }

    function waitForSendRetry(delay) {
        return new Promise(function (resolve) {
            window.setTimeout(resolve, delay);
        });
    }

    function canRetryChatSend(allowRetry, capabilityEpoch, expectedClientMessageId) {
        return allowRetry && messageIdempotencyReady && capabilityEpoch === messageIdempotencyEpoch &&
            pendingClientMessage !== null && pendingClientMessage.id === expectedClientMessageId;
    }

    function fetchChatAttempt(options, timeoutMs, isAttachment) {
        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        const requestOptions = Object.assign({}, options);
        if (controller) requestOptions.signal = controller.signal;
        let timeoutId = null;
        const timeoutPromise = new Promise(function (_resolve, reject) {
            timeoutId = window.setTimeout(function () {
                if (controller) controller.abort();
                const error = new Error('The send request timed out');
                error.name = 'TimeoutError';
                reject(error);
            }, timeoutMs);
        });
        const request = fetch('api/chat.php', requestOptions).then(function (response) {
            return readChatSendResponse(response, isAttachment).then(function (data) {
                return {response: response, data: data};
            });
        });
        return Promise.race([request, timeoutPromise]).finally(function () {
            if (timeoutId !== null) window.clearTimeout(timeoutId);
        });
    }

    function fetchChatWithRetry(
        options,
        allowRetry,
        capabilityEpoch,
        expectedClientMessageId,
        timeoutMs,
        isAttachment,
        attempt
    ) {
        const currentAttempt = attempt || 1;
        return fetchChatAttempt(options, timeoutMs, isAttachment).then(function (result) {
            const response = result.response;
            if (canRetryChatSend(allowRetry, capabilityEpoch, expectedClientMessageId) &&
                response.status >= 500 && response.status <= 599 &&
                currentAttempt < MAX_SEND_ATTEMPTS) {
                return waitForSendRetry(350).then(function () {
                    if (!canRetryChatSend(allowRetry, capabilityEpoch, expectedClientMessageId)) {
                        return result.data;
                    }
                    return fetchChatWithRetry(
                        options,
                        allowRetry,
                        capabilityEpoch,
                        expectedClientMessageId,
                        timeoutMs,
                        isAttachment,
                        currentAttempt + 1
                    );
                });
            }
            return result.data;
        }, function (error) {
            if (!canRetryChatSend(allowRetry, capabilityEpoch, expectedClientMessageId) ||
                currentAttempt >= MAX_SEND_ATTEMPTS) {
                throw error;
            }
            return waitForSendRetry(350).then(function () {
                if (!canRetryChatSend(allowRetry, capabilityEpoch, expectedClientMessageId)) throw error;
                return fetchChatWithRetry(
                    options,
                    allowRetry,
                    capabilityEpoch,
                    expectedClientMessageId,
                    timeoutMs,
                    isAttachment,
                    currentAttempt + 1
                );
            });
        });
    }

    function sendFailureMessage(status, isAttachment, payload) {
        const errorCode = payload && typeof payload.error_code === 'string'
            ? payload.error_code
            : '';
        if (Object.prototype.hasOwnProperty.call(CHAT_SEND_FAILURE_MESSAGES, errorCode)) {
            return translateUi(
                'send.error.' + errorCode,
                {},
                CHAT_SEND_FAILURE_MESSAGES[errorCode]
            );
        }
        if (status === 409) {
            return translateUi(
                'send.error.conversation_changed',
                {},
                'The conversation changed. Edit the draft to create a new send.'
            );
        }
        if (status === 429) {
            return translateUi(
                'send.error.temporarily_limited',
                {},
                'Sending is temporarily limited. Check the conversation, then retry this unchanged draft shortly.'
            );
        }
        if (status === 401) {
            return translateUi(
                'send.error.session_expired',
                {},
                'Your session expired. Sign in again before retrying.'
            );
        }
        if (status === 413) {
            return isAttachment
                ? translateUi('send.error.file_too_large', {}, 'This file is too large and was not sent.')
                : translateUi('send.error.message_too_large', {}, 'This message is too large and was not sent.');
        }
        if (status === 403) {
            return translateUi(
                'send.error.permission_denied',
                {},
                'You do not have permission to send to this chat.'
            );
        }
        if (status === 415) {
            return isAttachment
                ? translateUi(
                    'send.error.unsupported_attachment_type',
                    {},
                    'This attachment type is not supported.'
                )
                : translateUi('send.error.unsupported_message_format', {}, 'This message format is not supported.');
        }
        if (status === 400 || status === 422) {
            return isAttachment
                ? translateUi(
                    'send.error.attachment_checks_failed',
                    {},
                    'This attachment did not pass the required checks. Check the file and try again.'
                )
                : translateUi(
                    'send.error.invalid_draft',
                    {},
                    'This message is invalid. Check the draft and try again.'
                );
        }
        if (status >= 500 && status <= 599) {
            return translateUi(
                'send.error.send_outcome_unknown',
                {},
                'Delivery could not be confirmed. Check the conversation before retrying this unchanged draft.'
            );
        }
        if (isAttachment) {
            return translateUi(
                'send.error.attachment_outcome_unknown',
                {},
                'Attachment delivery could not be confirmed. Check the conversation before retrying this unchanged draft.'
            );
        }
        return translateUi(
            'send.error.send_outcome_unknown',
            {},
            'Delivery could not be confirmed. Check the conversation before retrying this unchanged draft.'
        );
    }

    function readChatSendResponse(response, isAttachment) {
        return response.text().then(function (body) {
            let payload = null;
            if (body) {
                try {
                    const parsed = JSON.parse(body);
                    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
                        payload = parsed;
                    }
                } catch (error) {
                    payload = null;
                }
            }

            if (!response.ok || !payload || payload.success !== true) {
                const errorCode = payload && typeof payload.error_code === 'string'
                    ? payload.error_code
                    : '';
                const malformedSuccessfulResponse = response.ok &&
                    (!payload || typeof payload.success !== 'boolean');
                return {
                    success: false,
                    message: sendFailureMessage(response.status, isAttachment, payload),
                    status: response.status,
                    error_code: errorCode,
                    delivery_unconfirmed: malformedSuccessfulResponse || response.status >= 500 ||
                        ['send_outcome_unknown', 'messaging_unavailable', 'request_failed'].includes(errorCode)
                };
            }
            return payload;
        });
    }

    function clearAttachmentSendError() {
        const preview = document.getElementById('attachmentPreview');
        if (!preview) return;
        preview.removeAttribute('aria-invalid');
        const error = preview.querySelector('.attachment-send-error');
        if (error) error.remove();
    }

    function showAttachmentSendError(message) {
        const preview = document.getElementById('attachmentPreview');
        const content = document.getElementById('previewContent');
        if (!preview || !content) return;
        clearAttachmentSendError();
        const error = document.createElement('div');
        error.className = 'attachment-send-error text-danger small mt-2';
        error.setAttribute('role', 'alert');
        error.setAttribute('aria-live', 'assertive');
        error.textContent = message;
        content.appendChild(error);
        preview.setAttribute('aria-invalid', 'true');
    }

    function restoreComposerAfterFailedSend(input) {
        window.setTimeout(function () {
            if (document.activeElement !== input && input.isConnected) {
                input.focus({preventScroll: true});
            }
        }, 0);
    }

    function renderAcknowledgedMessage(data) {
        if (typeof window.cancelNewMessagePoll === 'function') window.cancelNewMessagePoll();
        if (data.message && !document.querySelector('#messagesList [data-message-id="' + data.message.id + '"]')) {
            renderMessages([data.message], false, true);
        }
        loadChats();
    }

    function notifyChatSendState(chatId, state, attemptId) {
        if (typeof window.dispatchEvent !== 'function' || typeof window.CustomEvent !== 'function') return;
        window.dispatchEvent(new CustomEvent('pm:send-state', {
            detail: {chatId: Number(chatId), state: state, attemptId: String(attemptId || '')}
        }));
    }

    function sendMessage() {
        // Keyboard submission bypasses a disabled button. Keep one logical send
        // in flight so rapid Enter presses cannot create parallel legacy sends
        // or race the button/composer finalizers.
        if (chatSendInFlight) return;
        if (window.pmVoiceComposerBusy === true) {
            showToast('Finish or discard the voice recording before sending another message.', 'warning');
            return;
        }

        const input = document.getElementById('messageInput');
        const content = input.value.trim();
        const attachment = currentAttachment;

        if ((!content && !attachment) || !currentChatId) {
            if (!currentChatId) {
                showToast('Please select a chat first', 'warning');
            } else {
                showToast('Please enter a message or attach a file', 'warning');
            }
            return;
        }

        const replyToId = input.dataset.replyTo;
        const isAttachment = Boolean(attachment);
        const useIdempotency = messageIdempotencyReady === true;
        const capabilityEpoch = messageIdempotencyEpoch;
        const semanticEpoch = clientSendSemanticEpoch;
        const chatIdAtSend = String(currentChatId);
        const localDeliveryAttemptId = 'local-' + String(++chatSendUiAttempt);
        let clientMessageId = null;
        if (useIdempotency) {
            try {
                clientMessageId = clientMessageIdFor(
                    isAttachment ? 'attachment' : 'text',
                    currentChatId,
                    content,
                    replyToId,
                    attachment
                );
            } catch (error) {
                showToast(error.message || 'This message cannot be sent securely in this browser.', 'error');
                return;
            }
        } else {
            clearPendingClientMessage();
        }
        const deliveryAttemptId = clientMessageId || localDeliveryAttemptId;
        if (typeof window.cancelNewMessagePoll === 'function') window.cancelNewMessagePoll();

        let requestOptions;
        if (isAttachment) {
            const formData = new FormData();
            formData.append('action', 'upload_file');
            formData.append('chat_id', currentChatId);
            formData.append('file', attachment);
            if (useIdempotency) formData.append('client_message_id', clientMessageId);
            if (content) formData.append('caption', content);
            if (replyToId) formData.append('reply_to', replyToId);
            requestOptions = {
                method: 'POST',
                credentials: 'include',
                body: formData
            };
            clearAttachmentSendError();
        } else {
            const requestData = {
                action: 'send_message',
                chat_id: currentChatId,
                content: content
            };
            if (useIdempotency) requestData.client_message_id = clientMessageId;
            if (replyToId) requestData.reply_to = replyToId;
            requestOptions = {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify(requestData)
            };
        }

        const sendBtn = document.querySelector('.send-btn');
        if (!sendBtn || sendBtn.disabled) return;
        const originalButtonChildren = Array.from(sendBtn.childNodes, function (node) {
            return node.cloneNode(true);
        });
        const originalLabel = sendBtn.getAttribute('aria-label') || 'Send message';
        let sendSucceeded = false;
        const spinner = document.createElement('i');
        spinner.className = 'fas fa-spinner fa-spin';
        spinner.setAttribute('aria-hidden', 'true');
        sendBtn.replaceChildren(spinner);
        sendBtn.setAttribute('aria-label', isAttachment ? 'Sending attachment' : 'Sending message');
        sendBtn.setAttribute('aria-busy', 'true');
        sendBtn.disabled = true;

        if (isAttachment) showToast('Sending file...', 'info', 2000);

        chatSendInFlight = true;
        notifyChatSendState(currentChatId, 'sending', deliveryAttemptId);
        Promise.resolve()
            .then(function () {
                return fetchChatWithRetry(
                    requestOptions,
                    useIdempotency,
                    capabilityEpoch,
                    clientMessageId,
                    isAttachment ? CHAT_SEND_ATTACHMENT_TIMEOUT_MS : CHAT_SEND_TEXT_TIMEOUT_MS,
                    isAttachment
                );
            })
            .then(function (data) {
                if (!data.success) {
                    notifyChatSendState(
                        chatIdAtSend,
                        data.delivery_unconfirmed ? 'unconfirmed' : 'rejected',
                        deliveryAttemptId
                    );
                    if (isAttachment) showAttachmentSendError(data.message);
                    showToast(data.message, 'error');
                    return;
                }

                sendSucceeded = true;
                const composerIsUnchanged = semanticEpoch === clientSendSemanticEpoch &&
                    String(currentChatId) === chatIdAtSend;
                clearPendingClientMessage(clientMessageId);
                if (composerIsUnchanged) {
                    input.value = '';
                    if (isAttachment) clearAttachment();
                    clearReply();
                } else if (isAttachment && currentAttachment === attachment) {
                    const latestDraft = input.value;
                    const latestPlaceholder = input.placeholder;
                    const latestReplyTo = input.dataset.replyTo;
                    clearAttachment();
                    input.value = latestDraft;
                    input.placeholder = latestReplyTo ? latestPlaceholder : 'Type a message...';
                }
                input.dispatchEvent(new Event('input', {bubbles: true}));
                notifyChatSendState(chatIdAtSend, 'sent', deliveryAttemptId);
                renderAcknowledgedMessage(data);
                if (isAttachment) showToast('File sent successfully!', 'success', 2000);
            })
            .catch(function (error) {
                notifyChatSendState(chatIdAtSend, 'unconfirmed', deliveryAttemptId);
                console.error(isAttachment ? 'Send file error:' : 'Send message error:', error);
                const message = translateUi(
                    'send.error.connection_failed',
                    {},
                    'Delivery could not be confirmed because the connection failed. ' +
                        'Check the conversation before retrying this unchanged draft.'
                );
                if (isAttachment) showAttachmentSendError(message);
                showToast(message, 'error');
            })
            .finally(function () {
                chatSendInFlight = false;
                sendBtn.replaceChildren(...originalButtonChildren);
                sendBtn.setAttribute('aria-label', originalLabel);
                sendBtn.setAttribute('aria-busy', 'false');
                sendBtn.disabled = false;
                if (!sendSucceeded) restoreComposerAfterFailedSend(input);
            });
    }

    function handleKeyPress(event) {
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            sendMessage();
        }
    }

    function handleTyping() {
        if (!currentChatId) return;

        const chatId = String(currentChatId);
        if (typingChatId && typingChatId !== chatId) window.stopActiveTyping();
        typingChatId = chatId;
        const now = Date.now();
        const timeSinceLastTyping = now - lastTypingTime;

        // Only send typing indicator if it's been more than 1 second since last send
        if (timeSinceLastTyping > 1000) {
            lastTypingTime = now;

            // Send typing indicator (but don't await response)
            fetch('api/chat.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    action: 'set_typing',
                    chat_id: chatId,
                    is_typing: true
                })
            }).catch(error => {
                // Silently handle typing indicator errors
                console.debug('Typing indicator error:', error);
            });
        }

        // Stop typing after 3 seconds of inactivity
        clearTimeout(typingTimeout);
        typingTimeout = setTimeout(function () {
            typingTimeout = null;
            if (typingChatId === chatId) {
                fetch('api/chat.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        action: 'set_typing',
                        chat_id: chatId,
                        is_typing: false
                    })
                }).catch(error => {
                    // Silently handle typing indicator errors
                    console.debug('Stop typing indicator error:', error);
                });
                typingChatId = null;
                lastTypingTime = 0;
            }
        }, 3000);
    }

    window.stopActiveTyping = function stopActiveTyping() {
        if (typingTimeout !== null) {
            window.clearTimeout(typingTimeout);
            typingTimeout = null;
        }
        const chatId = typingChatId;
        typingChatId = null;
        lastTypingTime = 0;
        if (!chatId) return;
        fetch('api/chat.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({action: 'set_typing', chat_id: chatId, is_typing: false})
        }).catch(function (error) {
            console.debug('Stop typing indicator error:', error);
        });
    };

    // Enhanced status updates
    function updateOnlineStatus() {
        if (!currentUser) return;

        fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'update_status'
            })
        }, AUTH_REQUEST_TIMEOUT_MS)
            .catch(error => console.debug('Status update error:', error));
    }

    // Search and new chat functions
    function showNewChatModal() {
        new bootstrap.Modal(document.getElementById('newChatModal')).show();
    }

    function searchUsers() {
        const query = document.getElementById('userSearchInput').value.trim();

        if (query.length < 2) {
            document.getElementById('userSearchResults').innerHTML =
                '<div class="text-center py-3">' +
                '<i class="fas fa-search fa-2x mb-2 text-muted"></i>' +
                '<div class="text-muted">Type at least 2 characters to search</div>' +
                '</div>';
            return;
        }

        if (query.length > 50) {
            showToast('Search query is too long. Please use fewer characters.', 'warning');
            return;
        }

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'search_users',
                query: query
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    if (data.users.length === 0) {
                        document.getElementById('userSearchResults').innerHTML =
                            '<div class="text-center py-3">' +
                            '<i class="fas fa-user-slash fa-2x mb-2 text-muted"></i>' +
                            '<div class="text-muted">' + escapeHtml(translateUi(
                                'people.none_matching',
                                {query: query},
                                'No users found for this search'
                            )) + '</div>' +
                            '</div>';
                    } else {
                        renderUserSearchResults(data.users);
                    }
                } else {
                    showToast('Search failed: ' + (data.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Search users error:', error);
                showToast('Search failed. Please check your connection.', 'error');
            });
    }

    function renderUserSearchResults(users) {
        const container = document.getElementById('userSearchResults');
        container.innerHTML = '';

        users.forEach(function (user) {
            const userDiv = document.createElement('div');
            userDiv.className = 'chat-item';
            userDiv.onclick = function () {
                startChatWithUser(user.id);
            };

            const avatar = user.avatar ?
                '<img src="' + user.avatar + '" alt="Avatar" class="avatar-image-fill">' :
                user.first_name.charAt(0).toUpperCase();

            const onlineStatus = user.is_online ?
                '<div class="online-indicator"></div>' : '';

            userDiv.innerHTML =
                '<div class="avatar-container">' +
                '<div class="chat-avatar">' + avatar + '</div>' +
                onlineStatus +
                '</div>' +
                '<div class="chat-info">' +
                '<div class="chat-name">' + user.first_name + ' ' + user.last_name + '</div>' +
                '<div class="chat-last-message">@' + user.username + '</div>' +
                '</div>';

            container.appendChild(userDiv);
        });
    }

    async function startChatWithUser(userId) {
        const userElement = event.currentTarget;
        const userName = userElement.querySelector('.chat-name').textContent;

        const confirmed = await showConfirmDialog(
            'Start New Chat',
            `Start a conversation with ${userName}?`,
            'Start Chat',
            'primary'
        );

        if (!confirmed) return;

        showToast('Creating chat...', 'info');

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'create_private_chat',
                user_id: userId
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    bootstrap.Modal.getInstance(document.getElementById('newChatModal')).hide();
                    showToast(`Chat with ${userName} created successfully!`, 'success');
                    loadChats();
                    // Auto-select the new chat
                    setTimeout(function () {
                        const chatItems = document.querySelectorAll('.chat-item');
                        if (chatItems.length > 0) {
                            chatItems[0].click();
                        }
                    }, 500);
                } else {
                    showToast('Failed to create chat: ' + (data.message || 'Unknown error'), 'error');
                }
            })
            .catch(error => {
                console.error('Create chat error:', error);
                showToast('Failed to create chat. Please try again.', 'error');
            });
    }

    // Chat info and search functions
    function showChatInfo() {
    if (!currentChatInfo) return;

    const content = document.getElementById('chatInfoContent');

    if (currentChatInfo.type === 'private' && currentChatInfo.other_user) {
        const user = currentChatInfo.other_user;
        const avatar = user.avatar ?
            '<img src="' + user.avatar + '" alt="Avatar" class="avatar-image-fill">' :
            user.first_name.charAt(0).toUpperCase();

        const status = user.is_online ?
            '<span class="text-success"><i class="fas fa-circle me-1 online-status-dot"></i>Online</span>' :
            'Last seen ' + formatTime(user.last_seen);

        // Build additional profile information based on privacy settings
        let additionalInfo = '';
        
        // Email (if user allows showing email)
        if (user.show_email && user.email) {
            additionalInfo += '<div class="profile-info-item mb-2">' +
                '<i class="fas fa-envelope me-2 text-muted"></i>' +
                '<span class="text-muted">Email:</span> ' + escapeHtml(user.email) +
                '</div>';
        }
        
        // Phone (if user allows showing phone)
        if (user.show_phone && user.phone) {
            additionalInfo += '<div class="profile-info-item mb-2">' +
                '<i class="fas fa-phone me-2 text-muted"></i>' +
                '<span class="text-muted">Phone:</span> ' + escapeHtml(user.phone) +
                '</div>';
        }

        // Bio (if user allows showing bio and bio exists)
        let bioSection = '';
        if (user.show_bio && user.bio) {
            bioSection = '<div class="user-profile-bio mt-3">' +
                '<h6 class="text-muted mb-2"><i class="fas fa-user-circle me-2"></i>About</h6>' +
                '<div class="bio-content">' + escapeHtml(user.bio) + '</div>' +
                '</div>';
        }

        content.innerHTML =
            '<div class="user-profile-header">' +
            '<div class="user-profile-avatar">' + avatar + '</div>' +
            '<div class="user-profile-name">' + user.first_name + ' ' + user.last_name + '</div>' +
            '<div class="user-profile-username">@' + user.username + '</div>' +
            '<div class="user-profile-status">' + status + '</div>' +
            (additionalInfo ? '<div class="profile-additional-info mt-3">' + additionalInfo + '</div>' : '') +
            bioSection +
            '</div>' +
            '<div class="chat-info-section">' +
            '<h6><i class="fas fa-info-circle me-2"></i>Chat Details</h6>' +
            '<div class="row">' +
            '<div class="col-6">' +
            '<small class="text-muted">Chat Type</small>' +
            '<div>Private Chat</div>' +
            '</div>' +
            '<div class="col-6">' +
            '<small class="text-muted">Messages</small>' +
            '<div id="messageCount">Loading...</div>' +
            '</div>' +
            '</div>' +
            '</div>';
    }

    // Load additional info
    loadChatStats(document.getElementById('messageCount'));

    new bootstrap.Modal(document.getElementById('chatInfoModal')).show();
}

    function loadChatStats(targetElement) {
        const chatId = Number(currentChatId);
        const messageCountEl = targetElement || document.getElementById('messageCount');
        if (!Number.isSafeInteger(chatId) || chatId <= 0 || !messageCountEl) return;
        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'get_chat_stats',
                chat_id: chatId
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success && Number(currentChatId) === chatId && messageCountEl.isConnected) {
                    const messageCount = Number(data.message_count);
                    if (Number.isSafeInteger(messageCount) && messageCount >= 0) {
                        messageCountEl.removeAttribute('data-i18n');
                        messageCountEl.dataset.i18nNumber = String(messageCount);
                        messageCountEl.textContent = formatUiNumber(messageCount);
                    } else {
                        messageCountEl.removeAttribute('data-i18n-number');
                        messageCountEl.dataset.i18n = 'common.unavailable';
                        messageCountEl.textContent = translateUi('common.unavailable', {}, 'Unavailable');
                    }
                } else if (Number(currentChatId) === chatId && messageCountEl.isConnected) {
                    messageCountEl.removeAttribute('data-i18n-number');
                    messageCountEl.dataset.i18n = 'common.unavailable';
                    messageCountEl.textContent = translateUi('common.unavailable', {}, 'Unavailable');
                }
            })
            .catch(error => {
                console.error('Load chat stats error:', error);
                if (Number(currentChatId) === chatId && messageCountEl.isConnected) {
                    messageCountEl.removeAttribute('data-i18n-number');
                    messageCountEl.dataset.i18n = 'common.unavailable';
                    messageCountEl.textContent = translateUi('common.unavailable', {}, 'Unavailable');
                }
            });
    }

    function showChatSearch() {
        new bootstrap.Modal(document.getElementById('chatSearchModal')).show();
        setTimeout(function () {
            document.getElementById('chatSearchInput').focus();
        }, 300);
    }

    let searchTimeout;

    function searchInChat() {
        const query = document.getElementById('chatSearchInput').value.trim();

        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(function () {
            if (query.length < 2) {
                document.getElementById('chatSearchResults').innerHTML =
                    '<div class="text-muted text-center py-3">' +
                    '<i class="fas fa-search fa-2x mb-2"></i>' +
                    '<div>Type to search messages</div>' +
                    '</div>';
                return;
            }

            fetch('api/chat.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    action: 'search_messages',
                    chat_id: currentChatId,
                    query: query
                })
            })
                .then(response => response.json())
                .then(data => {
                    if (data.success) {
                        renderSearchResults(data.messages, query);
                    }
                })
                .catch(error => console.error('Search messages error:', error));
        }, 300);
    }

    function renderSearchResults(messages, query) {
        const container = document.getElementById('chatSearchResults');

        if (messages.length === 0) {
            container.innerHTML =
                '<div class="text-muted text-center py-3">' +
                '<i class="fas fa-search fa-2x mb-2"></i>' +
                '<div>No messages found</div>' +
                '</div>';
            return;
        }

        container.innerHTML = '';

        messages.forEach(function (message) {
            const highlightedContent = highlightText(message.content, query);

            const resultDiv = document.createElement('div');
            resultDiv.className = 'search-result-item';
            resultDiv.onclick = function () {
                jumpToMessage(message.id);
            };

            resultDiv.innerHTML =
                '<div><strong>' + message.first_name + ' ' + message.last_name + ':</strong></div>' +
                '<div>' + highlightedContent + '</div>' +
                '<div class="search-result-meta">' + formatTime(message.created_at) + '</div>';

            container.appendChild(resultDiv);
        });
    }

    function highlightText(text, query) {
        const regex = new RegExp('(' + escapeRegExp(query) + ')', 'gi');
        return escapeHtml(text).replace(regex, '<span class="search-highlight">$1</span>');
    }

    function escapeRegExp(string) {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }

    function jumpToMessage(messageId) {
        // Find the message in current view
        const messageElement = document.querySelector('[data-message-id="' + messageId + '"]');
        if (messageElement) {
            messageElement.scrollIntoView({behavior: 'smooth', block: 'center'});
            messageElement.style.backgroundColor = 'rgba(0, 136, 204, 0.3)';
            messageElement.style.transition = 'background-color 0.3s ease';

            setTimeout(function () {
                messageElement.style.backgroundColor = '';
            }, 2000);
        } else {
            showToast('Message not found in current view');
        }
    }

    function showUserProfile(userId) {
        selectedUserId = userId;

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'get_user_profile',
                user_id: userId
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    renderUserProfile(data.user);
                }
            })
            .catch(error => console.error('Get user profile error:', error));
    }

    function renderUserProfile(user) {
        const content = document.getElementById('userProfileContent');

        const avatar = user.avatar ?
            '<img src="' + user.avatar + '" alt="Avatar" class="avatar-image-fill">' :
            user.first_name.charAt(0).toUpperCase();

        const status = user.is_online ?
            '<span class="text-success"><i class="fas fa-circle me-1 online-status-dot"></i>Online</span>' :
            'Last seen ' + formatTime(user.last_seen);

        content.innerHTML =
            '<div class="user-profile-header">' +
            '<div class="user-profile-avatar">' + avatar + '</div>' +
            '<div class="user-profile-name">' + user.first_name + ' ' + user.last_name + '</div>' +
            '<div class="user-profile-username">@' + user.username + '</div>' +
            '<div class="user-profile-status">' + status + '</div>' +
            (user.bio ? '<div class="user-profile-bio"><strong>Bio:</strong><br>' + escapeHtml(user.bio) + '</div>' : '') +
            (user.phone ? '<div class="mt-3"><strong>Phone:</strong> ' + escapeHtml(user.phone) + '</div>' : '') +
            '</div>';

        // Show/hide send message button
        const sendBtn = document.getElementById('sendMessageBtn');
        if (user.id === currentUser.id) {
            sendBtn.style.display = 'none';
        } else {
            sendBtn.style.display = 'inline-block';
        }

        new bootstrap.Modal(document.getElementById('userProfileModal')).show();
    }

    function startChatFromProfile() {
        if (!selectedUserId) return;

        bootstrap.Modal.getInstance(document.getElementById('userProfileModal')).hide();

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'create_private_chat',
                user_id: selectedUserId
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    loadChats();
                }
            })
            .catch(error => console.error('Create chat error:', error));
    }

    // File attachment functions
    function notifyAttachmentStateChanged() {
        if (typeof window.dispatchEvent === 'function' && typeof window.CustomEvent === 'function') {
            window.dispatchEvent(new window.CustomEvent('pm:attachment-state-change'));
        }
    }

    function showAttachmentOptions() {
        new bootstrap.Modal(document.getElementById('attachmentModal')).show();
    }

    function selectFileType(accept) {
        bootstrap.Modal.getInstance(document.getElementById('attachmentModal')).hide();

        const fileInput = document.getElementById('fileInput');
        fileInput.accept = accept;
        fileInput.click();
    }

    function handleFileSelect(event) {
        const file = event.target.files[0];
        if (!file) return;
        if (window.pmVoiceComposerBusy === true) {
            event.target.value = '';
            showToast('Finish or discard the voice recording before choosing an attachment.', 'warning');
            return;
        }

        // Validate file size (non-empty, 50MB max)
        if (file.size < 1) {
            event.target.value = '';
            showToast('Empty files cannot be sent.', 'error');
            return;
        }
        if (file.size > 50 * 1024 * 1024) {
            event.target.value = '';
            showToast('File size must be less than 50MB. Please choose a smaller file.', 'error');
            return;
        }

        // Validate file type
        if (!window.isSupportedChatAttachment(file)) {
            event.target.value = '';
            showToast('File type not supported. Please choose a different file.', 'error');
            return;
        }

        markClientSendSemanticsChanged();
        clearAttachmentSendError();
        currentAttachment = file;
        showAttachmentPreview(file);
        notifyAttachmentStateChanged();
        showToast('File ready to send: ' + file.name, 'success');
    }

    function showAttachmentPreview(file) {
        const preview = document.getElementById('attachmentPreview');
        const content = document.getElementById('previewContent');
        content.replaceChildren();
        preview.classList.remove('d-none');

        if (file.type.startsWith('image/')) {
            const reader = new FileReader();
            reader.onload = function () {
                if (currentAttachment !== file || typeof reader.result !== 'string') return;
                renderAttachmentPreviewContent(content, file, reader.result);
            };
            reader.onerror = function () {
                if (currentAttachment !== file) return;
                renderAttachmentPreviewContent(content, file, null);
            };
            reader.readAsDataURL(file);
        } else {
            renderAttachmentPreviewContent(content, file, null);
        }

        // Focus on message input for caption
        const messageInput = document.getElementById('messageInput');
        messageInput.placeholder = 'Add a caption...';
        messageInput.focus();
    }

    function renderAttachmentPreviewContent(content, file, imageSource) {
        const row = document.createElement('div');
        row.className = 'd-flex align-items-center mb-3';

        if (typeof imageSource === 'string') {
            const image = document.createElement('img');
            image.src = imageSource;
            image.alt = 'Preview';
            image.className = 'attachment-preview-image';
            row.appendChild(image);
        } else {
            const fileIcon = getFileIcon(file.name);
            const iconContainer = document.createElement('div');
            iconContainer.className = 'file-icon me-3 attachment-preview-file-icon';
            const icon = document.createElement('i');
            icon.className = 'fas ' + fileIcon.icon;
            iconContainer.appendChild(icon);
            row.appendChild(iconContainer);
        }

        const details = document.createElement('div');
        details.className = 'flex-grow-1';
        const name = document.createElement('div');
        name.className = 'fw-bold';
        name.textContent = file.name;
        const size = document.createElement('div');
        size.className = 'text-muted small';
        size.textContent = formatFileSize(file.size);
        const ready = document.createElement('div');
        ready.className = 'text-success small mt-1';
        const readyIcon = document.createElement('i');
        readyIcon.className = 'fas fa-check-circle me-1';
        ready.append(readyIcon, document.createTextNode('Ready to send'));
        details.append(name, size, ready);
        row.appendChild(details);
        content.replaceChildren(row);
    }

    function clearAttachment() {
        if (typeof window.releaseAttachmentPreviewObjectUrl === 'function') {
            window.releaseAttachmentPreviewObjectUrl();
        }
        markClientSendSemanticsChanged();
        clearAttachmentSendError();
        currentAttachment = null;
        document.getElementById('attachmentPreview').classList.add('d-none');
        document.getElementById('fileInput').value = '';

        // Reset message input placeholder
        const messageInput = document.getElementById('messageInput');
        if (!messageInput.dataset.replyTo && !messageInput.dataset.editMessageId) {
            messageInput.placeholder = 'Type a message...';
        }
        notifyAttachmentStateChanged();
    }

    function showImagePreview(imageSrc) {
        document.getElementById('previewImage').src = imageSrc;
        new bootstrap.Modal(document.getElementById('imagePreviewModal')).show();
    }

    function getFileIcon(filename) {
        const extension = filename.split('.').pop().toLowerCase();

        const iconMap = {
            // Images
            'jpg': {icon: 'fa-image', color: '#4CAF50'},
            'jpeg': {icon: 'fa-image', color: '#4CAF50'},
            'png': {icon: 'fa-image', color: '#4CAF50'},
            'gif': {icon: 'fa-image', color: '#4CAF50'},
            'webp': {icon: 'fa-image', color: '#4CAF50'},

            // Documents
            'pdf': {icon: 'fa-file-pdf', color: '#F44336'},
            'doc': {icon: 'fa-file-word', color: '#2196F3'},
            'docx': {icon: 'fa-file-word', color: '#2196F3'},
            'xls': {icon: 'fa-file-excel', color: '#4CAF50'},
            'xlsx': {icon: 'fa-file-excel', color: '#4CAF50'},
            'ppt': {icon: 'fa-file-powerpoint', color: '#FF9800'},
            'pptx': {icon: 'fa-file-powerpoint', color: '#FF9800'},
            'txt': {icon: 'fa-file-alt', color: '#9E9E9E'},

            // Archives
            'zip': {icon: 'fa-file-archive', color: '#795548'},
            'rar': {icon: 'fa-file-archive', color: '#795548'},
            '7z': {icon: 'fa-file-archive', color: '#795548'},

            // Audio
            'mp3': {icon: 'fa-file-audio', color: '#E91E63'},
            'wav': {icon: 'fa-file-audio', color: '#E91E63'},
            'flac': {icon: 'fa-file-audio', color: '#E91E63'},

            // Video
            'mp4': {icon: 'fa-file-video', color: '#9C27B0'},
            'avi': {icon: 'fa-file-video', color: '#9C27B0'},
            'mkv': {icon: 'fa-file-video', color: '#9C27B0'},

            // Code
            'js': {icon: 'fa-file-code', color: '#FFC107'},
            'html': {icon: 'fa-file-code', color: '#FF5722'},
            'css': {icon: 'fa-file-code', color: '#2196F3'},
            'php': {icon: 'fa-file-code', color: '#673AB7'},
            'py': {icon: 'fa-file-code', color: '#4CAF50'},
            'java': {icon: 'fa-file-code', color: '#FF9800'}
        };

        return iconMap[extension] || {icon: 'fa-file', color: '#607D8B'};
    }

    function formatFileSize(bytes) {
        if (window.PmI18n && typeof window.PmI18n.formatBytes === 'function') {
            return window.PmI18n.formatBytes(bytes);
        }
        if (bytes === 0) return '0 Bytes';

        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));

        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    // Refresh functions
    function refreshChats() {
        if (currentUser) {
            loadChats();
        }
    }

    function checkForNewMessages() {
        if (!currentChatId || isLoadingMessages) return;
        const chatContent = document.getElementById('chatContent');
        const main = document.querySelector('.main-container');
        const messagesList = document.getElementById('messagesList');
        if (!chatContent || !messagesList || chatContent.classList.contains('d-none') ||
            chatContent.inert || (main && main.classList.contains('settings-mode'))) return;

        const requestChatId = String(currentChatId);
        if (newMessagePollController && newMessagePollChatId === requestChatId) return;
        if (newMessagePollController) newMessagePollController.abort();

        const cursor = newMessagePollCursors.get(requestChatId);
        const currentLastMessageId = Number.isSafeInteger(cursor) && cursor > 0 ? cursor : null;
        const requestData = currentLastMessageId
            ? {
                action: 'get_new_messages',
                chat_id: requestChatId,
                after_message_id: currentLastMessageId
            }
            : {
                // get_new_messages requires a positive cursor. Poll the latest page
                // so an empty conversation can receive its first message live.
                action: 'get_messages',
                chat_id: requestChatId,
                limit: 30
            };
        const requestEpoch = ++newMessagePollRequestEpoch;
        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        newMessagePollController = controller;
        newMessagePollChatId = requestChatId;
        const timeoutId = window.setTimeout(function () {
            if (requestEpoch === newMessagePollRequestEpoch && controller) controller.abort();
        }, 15000);

        fetch('api/chat.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            signal: controller ? controller.signal : undefined,
            body: JSON.stringify(requestData)
        })
            .then(response => response.json())
            .then(data => {
                if (requestEpoch !== newMessagePollRequestEpoch ||
                    String(currentChatId) !== requestChatId ||
                    messagesList !== document.getElementById('messagesList') ||
                    chatContent.classList.contains('d-none') ||
                    window.pmSuppressNewMessageAutoScroll === true ||
                    (main && main.classList.contains('settings-mode'))) return;

                if (data.success && Array.isArray(data.messages)) {
                    const newestMessage = data.messages.length
                        ? data.messages[data.messages.length - 1]
                        : null;
                    const newestId = Number(newestMessage && newestMessage.id);
                    if (Number.isSafeInteger(newestId) && newestId > 0) {
                        newMessagePollCursors.set(requestChatId, newestId);
                    } else if (!currentLastMessageId) {
                        newMessagePollCursors.set(requestChatId, null);
                    }

                    if (!currentLastMessageId) {
                        // This is recovery after an empty/failed authoritative load,
                        // not an incremental append onto a potentially bounded context.
                        isInitialLoad = true;
                        renderMessages(data.messages, false, false);
                        isInitialLoad = false;
                        hasMoreMessages = data.messages.length === 30;
                    } else if (data.messages.length > 0) {
                        const existingMessageIds = new Set();
                        messagesList.querySelectorAll('[data-message-id]').forEach(function (message) {
                            existingMessageIds.add(message.dataset.messageId);
                        });
                        const newMessages = data.messages.filter(function (message) {
                            return message && !existingMessageIds.has(String(message.id));
                        });
                        if (newMessages.length > 0) renderMessages(newMessages, false, true);
                    }
                }

                refreshMessageReadStatus(requestChatId);
            })
            .catch(function (error) {
                if (!error || error.name !== 'AbortError') {
                    console.error('Check new messages error:', error);
                }
            })
            .finally(function () {
                window.clearTimeout(timeoutId);
                if (requestEpoch !== newMessagePollRequestEpoch) return;
                newMessagePollController = null;
                newMessagePollChatId = null;
            });
    }

    window.cancelNewMessagePoll = function cancelNewMessagePoll() {
        newMessagePollRequestEpoch += 1;
        if (newMessagePollController) newMessagePollController.abort();
        newMessagePollController = null;
        newMessagePollChatId = null;
    };

    // Enhanced drag and drop for file uploads
    function setupDragAndDrop() {
        const container = document.getElementById('messagesContainer');

        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(function (eventName) {
            container.addEventListener(eventName, preventDefaults, false);
        });

        function preventDefaults(e) {
            e.preventDefault();
            e.stopPropagation();
        }

        ['dragenter', 'dragover'].forEach(function (eventName) {
            container.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(function (eventName) {
            container.addEventListener(eventName, unhighlight, false);
        });

        function highlight(e) {
            container.classList.add('dragover');
        }

        function unhighlight(e) {
            container.classList.remove('dragover');
        }

        container.addEventListener('drop', handleDrop, false);

        function handleDrop(e) {
            const dt = e.dataTransfer;
            const files = dt.files;

            if (files.length > 0) {
                handleFileSelect({target: {files: [files[0]], value: ''}});
            }
        }
    }

    // Initialize drag and drop when chat is loaded
    function initializeChatFeatures() {
        setupDragAndDrop();
        setupInfiniteScroll();
    }

    // Night mode toggle
    function toggleNightMode() {
        document.body.classList.toggle('light-mode');
        const isLightMode = document.body.classList.contains('light-mode');
        localStorage.setItem('lightMode', isLightMode);

        // Update moon/sun icon
        const nightBtn = document.querySelector('.fa-moon, .fa-sun');
        if (nightBtn) {
            nightBtn.className = isLightMode ? 'fas fa-sun' : 'fas fa-moon';
        }

        showToast(isLightMode ? '☀️ Light mode enabled' : '🌙 Dark mode enabled');
    }

    function showSettings() {
        // Hide chat list, show settings list
        document.getElementById('chatList').classList.add('d-none');
        document.getElementById('settingsList').classList.remove('d-none');

        // Hide chat content and welcome screen
        document.getElementById('chatContent').classList.add('d-none');
        document.getElementById('welcomeScreen').classList.add('d-none');

        // Make sure settings content is hidden initially
        document.getElementById('settingsContent').classList.add('d-none');

        // Update search placeholder
        document.getElementById('searchInput').placeholder = 'Search settings...';

        // Load user settings
        const loadPromise = loadUserSettings();

        showToast('⚙️ Settings opened');
        return loadPromise;
    }

    function loadUserSettings() {
        if (settingsLoadPromise) {
            return settingsLoadPromise;
        }

        userSettingsLoaded = false;
        settingsLoadPromise = fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'get_settings'
            })
        })
            .then(response => response.json())
            .then(data => {
                if (!data.success || !data.settings || typeof data.settings !== 'object') {
                    throw new Error(data.message || 'Failed to load settings');
                }
                window.userSettings = data.settings;
                userSettingsLoaded = true;
                applySettings(data.settings);
                return data.settings;
            })
            .catch(error => {
                console.error('Load settings error:', error);
                return null;
            })
            .finally(() => {
                settingsLoadPromise = null;
            });

        return settingsLoadPromise;
    }

    function applySettings(settings) {
        // Apply theme
        if (settings.theme === 'light') {
            document.body.classList.add('light-mode');
        } else {
            document.body.classList.remove('light-mode');
        }

        // Apply font size
        const fontSizes = ['small', 'medium', 'large', 'extra-large'];
        fontSizes.forEach(size => document.body.classList.remove('font-size-' + size));
        const fontSize = fontSizes.includes(settings.font_size) ? settings.font_size : 'medium';
        document.body.classList.add('font-size-' + fontSize);

        // Apply other visual settings
        const chatBackgrounds = ['gradient1', 'gradient2', 'solid'];
        chatBackgrounds.forEach(background => document.body.classList.remove('bg-' + background));
        if (chatBackgrounds.includes(settings.chat_background)) {
            document.body.classList.add('bg-' + settings.chat_background);
        }
    }

    function updateSettings(settingsToUpdate) {
        if (!settingsToUpdate || typeof settingsToUpdate !== 'object') {
            return Promise.resolve();
        }

        const updates = Object.keys(settingsToUpdate).map(key => {
            return queueSettingUpdate(key, settingsToUpdate[key]);
        });
        return Promise.all(updates);
    }

    function queueSettingUpdate(key, value) {
        window.userSettings = window.userSettings || {};
        let state = settingsUpdateQueues[key];

        if (!state) {
            state = {
                confirmedValue: window.userSettings[key],
                desiredValue: value,
                version: 1,
                promise: null
            };
            settingsUpdateQueues[key] = state;
        } else {
            state.desiredValue = value;
            state.version += 1;
        }

        window.userSettings[key] = value;
        applySettings(window.userSettings);

        if (!state.promise) {
            pendingSettingsUpdateCount += 1;
            if (pendingSettingsUpdateCount === 1) {
                showLoading('Updating settings...');
            }
            state.promise = processSettingUpdateQueue(key, state).finally(() => {
                if (settingsUpdateQueues[key] === state) {
                    delete settingsUpdateQueues[key];
                }
                pendingSettingsUpdateCount = Math.max(0, pendingSettingsUpdateCount - 1);
                if (pendingSettingsUpdateCount === 0) {
                    hideLoading();
                }
            });
        }

        return state.promise;
    }

    async function processSettingUpdateQueue(key, state) {
        while (true) {
            const requestVersion = state.version;
            const requestedValue = state.desiredValue;
            let data = null;

            try {
                const response = await fetch('api/settings.php', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    credentials: 'include',
                    body: JSON.stringify({
                        action: 'update_settings',
                        settings: {[key]: requestedValue}
                    })
                });
                data = await response.json();
                if (!response.ok || !data.success) {
                    throw new Error(data.message || 'Failed to update settings');
                }
                state.confirmedValue = requestedValue;
            } catch (error) {
                console.error('Update settings error:', error);
                if (requestVersion === state.version) {
                    window.userSettings[key] = state.confirmedValue;
                    applySettings(window.userSettings);
                    syncSettingControl(key, state.confirmedValue);
                    const message = error && error.message
                        ? translateUiText(error.message)
                        : translateUi('api.settings_update_failed', {}, 'Failed to update settings');
                    showToast('❌ ' + message, 'error');
                    return;
                }
            }

            if (requestVersion === state.version) {
                window.userSettings[key] = state.confirmedValue;
                applySettings(window.userSettings);
                syncSettingControl(key, state.confirmedValue);
                showToast('✅ Settings updated successfully', 'success');
                return;
            }
        }
    }

    function syncSettingControl(key, value) {
        document.querySelectorAll('[data-pm-setting]').forEach(function (control) {
            if (control.dataset.pmSetting !== key) return;
            if (control.type === 'checkbox') {
                control.checked = key === 'theme' ? value === 'dark' : Boolean(value);
            } else {
                control.value = value == null ? '' : String(value);
            }
        });
    }


    function showSettingsSection(section) {
        activeSettingsSection = section;
        // Only hide settings list on mobile, keep it visible on desktop
        if (window.innerWidth <= 768) {
            document.getElementById('settingsList').classList.add('d-none');
            hideMobileSidebar();
        }
        document.getElementById('settingsContent').classList.remove('d-none');

        // Rest of the function stays the same...
        // Update active item
        document.querySelectorAll('.settings-item').forEach(item => {
            item.classList.remove('active');
        });

        // Find the settings item that matches the section and make it active
        const settingsItems = document.querySelectorAll('.settings-item');
        settingsItems.forEach(item => {
            if (item.onclick && item.onclick.toString().includes(`'${section}'`)) {
                item.classList.add('active');
            }
        });

        const contentArea = document.getElementById('settingsContentArea');
        const titleElement = document.getElementById('settingsTitle');

        const renderSection = function () {
            switch (section) {
            case 'profile':
                titleElement.textContent = 'Profile';
                contentArea.innerHTML = getProfileSettingsHTML();
                loadUserProfile();
                break;
            case 'account':
                titleElement.textContent = 'Account';
                contentArea.innerHTML = getAccountSettingsHTML();
                break;
            case 'notifications':
                titleElement.textContent = 'Notifications';
                contentArea.innerHTML = getNotificationSettingsHTML();
                break;
            case 'privacy':
                titleElement.textContent = 'Privacy & Security';
                contentArea.innerHTML = getPrivacySettingsHTML();
                break;
            case 'appearance':
                titleElement.textContent = 'Appearance';
                contentArea.innerHTML = getAppearanceSettingsHTML();
                break;
            case 'storage':
                titleElement.textContent = 'Storage Usage';
                contentArea.innerHTML = getStorageSettingsHTML();
                loadStorageUsage();
                break;
            case 'about':
                titleElement.textContent = 'About';
                contentArea.innerHTML = getAboutSettingsHTML();
                break;
            }
        };

        const sectionNeedsSettings = ['account', 'notifications', 'privacy', 'appearance', 'storage'].includes(section);
        if (sectionNeedsSettings && !userSettingsLoaded) {
            titleElement.textContent = {
                account: 'Account',
                notifications: 'Notifications',
                privacy: 'Privacy & Security',
                appearance: 'Appearance',
                storage: 'Storage Usage'
            }[section];
            const loadingState = document.createElement('div');
            loadingState.className = 'settings-section settings-load-state';
            loadingState.setAttribute('role', 'status');
            loadingState.textContent = 'Loading your settings…';
            contentArea.replaceChildren(loadingState);

            return loadUserSettings().then(function (settings) {
                if (activeSettingsSection !== section ||
                    document.getElementById('settingsContent').classList.contains('d-none')) {
                    return;
                }
                if (!settings) {
                    loadingState.setAttribute('role', 'alert');
                    loadingState.textContent = 'Your settings could not be loaded. Close and reopen Settings to try again.';
                    return;
                }
                renderSection();
            });
        }

        renderSection();
        return Promise.resolve();
    }

    function getProfileSettingsHTML() {
        return `
        <div class="user-info-card">
            <div class="profile-avatar-large profile-avatar-action" id="profileAvatarLarge" data-pm-action="change-avatar" role="button" tabindex="0">
                <i class="fas fa-user"></i>
                <div class="avatar-upload-overlay">
                    <i class="fas fa-camera"></i>
                </div>
            </div>
            <div class="user-name-large" id="profileNameLarge">Loading...</div>
            <div class="user-username" id="profileUsernameLarge">@loading</div>
            <input type="file" id="avatarUploadInput" accept="image/*" class="visually-hidden" data-pm-change="avatar-upload">
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-user"></i>
                Profile Information
            </div>
            
            <div class="settings-input-group">
                <label for="profileFirstName">First Name</label>
                <input type="text" class="settings-input" id="profileFirstName" placeholder="Enter your first name" minlength="2" maxlength="50" autocomplete="given-name">
            </div>
            
            <div class="settings-input-group">
                <label for="profileLastName">Last Name</label>
                <input type="text" class="settings-input" id="profileLastName" placeholder="Enter your last name" minlength="2" maxlength="50" autocomplete="family-name">
            </div>
            
            <div class="settings-input-group">
                <label for="profileUsername">Username</label>
                <input type="text" class="settings-input" id="profileUsername" placeholder="Enter your username" minlength="3" maxlength="50" autocomplete="username">
            </div>
            
            <div class="settings-input-group">
                <label for="profileBio">Bio</label>
                <textarea class="settings-input" id="profileBio" rows="3" placeholder="Tell us about yourself" maxlength="1000"></textarea>
            </div>
            
            <div class="settings-input-group">
                <label for="profilePhone">Phone (Optional)</label>
                <input type="tel" class="settings-input" id="profilePhone" placeholder="+1234567890" maxlength="20" autocomplete="tel">
            </div>
            
            <button class="settings-button" data-pm-action="update-profile">
                <i class="fas fa-save me-2"></i>Save Changes
            </button>
        </div>
    `;
    }

    function getAccountSettingsHTML() {
        const settings = window.userSettings || {};

        return `
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-key"></i>
                Password & Security
            </div>
            
            <div class="settings-input-group">
                <label for="currentPassword">Current Password</label>
                <input type="password" class="settings-input" id="currentPassword" placeholder="Enter current password">
            </div>
            
            <div class="settings-input-group">
                <label for="newPassword">New Password</label>
                <input type="password" class="settings-input" id="newPassword" placeholder="Enter 12–72 characters" minlength="12" maxlength="72">
            </div>
            
            <div class="settings-input-group">
                <label for="confirmPassword">Confirm New Password</label>
                <input type="password" class="settings-input" id="confirmPassword" placeholder="Confirm new password" minlength="12" maxlength="72">
            </div>
            
            <button class="settings-button" data-pm-action="change-password">
                <i class="fas fa-key me-2"></i>Change Password
            </button>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-shield-alt"></i>
                Two-Factor Authentication
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Two-Factor Authentication</div>
                    <div class="settings-option-description">Add an extra layer of security to your account</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="twoFactorToggle" aria-label="Two-factor authentication" ${settings.two_factor_enabled ? 'checked' : ''}
                           data-pm-action="toggle-2fa">
                    <span class="settings-slider"></span>
                </label>
            </div>
            
            <div id="twoFactorStatus" class="mt-3">
                ${settings.two_factor_enabled ?
            '<div class="alert alert-success"><i class="fas fa-check-circle me-2"></i>Two-Factor Authentication is enabled</div>' :
            '<div class="alert alert-info"><i class="fas fa-info-circle me-2"></i>Two-Factor Authentication is disabled</div>'
        }
            </div>
            
            ${settings.two_factor_enabled ?
            '<button class="settings-button" data-pm-action="generate-backup-codes"><i class="fas fa-download me-2"></i>Generate New Backup Codes</button>' :
            ''
        }
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-trash"></i>
                Danger Zone
            </div>
            
            <button class="settings-button danger" data-pm-action="delete-account">
                <i class="fas fa-trash me-2"></i>Delete Account
            </button>
        </div>
    `;
    }

    function getNotificationSettingsHTML() {
        const settings = window.userSettings || {};

        return `
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-bell"></i>
                Message Notifications
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Message Notifications</div>
                    <div class="settings-option-description">Receive notifications for new messages</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="messageNotifications" aria-label="Message notifications" ${settings.message_notifications ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="message_notifications">
                    <span class="settings-slider"></span>
                </label>
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Sound Notifications</div>
                    <div class="settings-option-description">Play sound for notifications</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="soundNotifications" aria-label="Sound notifications" ${settings.sound_notifications ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="sound_notifications">
                    <span class="settings-slider"></span>
                </label>
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Desktop Notifications</div>
                    <div class="settings-option-description">Show notifications on desktop</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="desktopNotifications" aria-label="Desktop notifications" ${settings.desktop_notifications ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="desktop_notifications">
                    <span class="settings-slider"></span>
                </label>
            </div>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-clock"></i>
                Do Not Disturb
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Do Not Disturb</div>
                    <div class="settings-option-description">Mute all notifications</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="doNotDisturb" aria-label="Do not disturb" ${settings.do_not_disturb ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="do_not_disturb">
                    <span class="settings-slider"></span>
                </label>
            </div>
        </div>
    `;
    }

    function getPrivacySettingsHTML() {
        const settings = window.userSettings || {};

        return `
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-eye"></i>
                Privacy
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Last Seen</div>
                    <div class="settings-option-description">Show when you were last online</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="showLastSeen" aria-label="Show last seen" ${settings.show_last_seen ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="show_last_seen">
                    <span class="settings-slider"></span>
                </label>
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Read Receipts</div>
                    <div class="settings-option-description">Show when you read messages</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="readReceipts" aria-label="Read receipts" ${settings.read_receipts ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="read_receipts">
                    <span class="settings-slider"></span>
                </label>
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Profile Photo</div>
                    <div class="settings-option-description">Show your profile photo to others</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="showProfilePhoto" aria-label="Show profile photo" ${settings.show_profile_photo ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="show_profile_photo">
                    <span class="settings-slider"></span>
                </label>
            </div>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-info-circle"></i>
                Public Profile Information
            </div>
            
            <div class="alert alert-info mb-3">
                <i class="fas fa-info-circle me-2"></i>
                <small>These settings control what information is visible to other users when they view your profile.</small>
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Show Email Address</div>
                    <div class="settings-option-description">Display your email address publicly</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="showEmail" aria-label="Show email address" ${settings.show_email ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="show_email">
                    <span class="settings-slider"></span>
                </label>
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Show Bio</div>
                    <div class="settings-option-description">Display your bio/description publicly</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="showBio" aria-label="Show bio" ${settings.show_bio ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="show_bio">
                    <span class="settings-slider"></span>
                </label>
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Show Phone Number</div>
                    <div class="settings-option-description">Display your phone number publicly</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="showPhone" aria-label="Show phone number" ${settings.show_phone ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="show_phone">
                    <span class="settings-slider"></span>
                </label>
            </div>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-users"></i>
                Who Can Contact Me
            </div>
            
            <div class="settings-input-group">
                <label for="whoCanMessage">Who can send me messages</label>
                <select class="settings-input" id="whoCanMessage" data-pm-action="update-setting" data-pm-setting="who_can_message">
                    <option value="everyone" ${settings.who_can_message === 'everyone' ? 'selected' : ''}>Everyone</option>
                    <option value="contacts" ${settings.who_can_message === 'contacts' ? 'selected' : ''}>My Contacts</option>
                    <option value="nobody" ${settings.who_can_message === 'nobody' ? 'selected' : ''}>Nobody</option>
                </select>
            </div>
        </div>
    `;
    }

    function getAppearanceSettingsHTML() {
        const settings = window.userSettings || {};
        const localePreference = window.PmI18n && typeof window.PmI18n.getPreference === 'function'
            ? window.PmI18n.getPreference()
            : 'auto';
        const localeOptions = [
            ['auto', 'System default', false],
            ['en', 'English', true],
            ['es', 'Español', true],
            ['zh-Hans', '简体中文', true],
            ['zh-Hant', '繁體中文', true],
            ['ar', 'العربية', true]
        ].map(function (option) {
            const localization = option[0] === 'auto' ? ' data-i18n="settings.system_default"' : '';
            return '<option value="' + option[0] + '"' + localization +
                (option[2] ? ' data-i18n-ignore' : '') + ' ' +
                (localePreference === option[0] ? 'selected' : '') + '>' + option[1] + '</option>';
        }).join('');

        return `
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-language"></i>
                Language
            </div>

            <div class="settings-input-group">
                <label for="appLanguage">Interface Language</label>
                <div class="settings-option-description">Choose the language used throughout Messenger</div>
                <select class="settings-input" id="appLanguage" data-pm-action="change-locale">
                    ${localeOptions}
                </select>
            </div>
        </div>

        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-moon"></i>
                Theme
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Dark Mode</div>
                    <div class="settings-option-description">Use dark theme</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="darkModeToggle" aria-label="Dark mode" ${settings.theme === 'dark' ? 'checked' : ''}
                           data-pm-action="update-theme-setting" data-pm-setting="theme">
                    <span class="settings-slider"></span>
                </label>
            </div>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-font"></i>
                Text Size
            </div>
            
            <div class="settings-input-group">
                <label for="fontSize">Font Size</label>
                <select class="settings-input" id="fontSize" data-pm-action="update-setting" data-pm-setting="font_size">
                    <option value="small" data-i18n="settings.small" ${settings.font_size === 'small' ? 'selected' : ''}>Small</option>
                    <option value="medium" data-i18n="settings.medium" ${settings.font_size === 'medium' ? 'selected' : ''}>Medium</option>
                    <option value="large" data-i18n="settings.large" ${settings.font_size === 'large' ? 'selected' : ''}>Large</option>
                    <option value="extra-large" data-i18n="settings.extra_large" ${settings.font_size === 'extra-large' ? 'selected' : ''}>Extra Large</option>
                </select>
            </div>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-image"></i>
                Chat Background
            </div>
            
            <div class="settings-input-group">
                <label for="chatBackground">Background</label>
                <select class="settings-input" id="chatBackground" data-pm-action="update-setting" data-pm-setting="chat_background">
                    <option value="default" data-i18n="settings.default" ${settings.chat_background === 'default' ? 'selected' : ''}>Default</option>
                    <option value="gradient1" data-i18n="settings.blue_gradient" ${settings.chat_background === 'gradient1' ? 'selected' : ''}>Blue Gradient</option>
                    <option value="gradient2" data-i18n="settings.purple_gradient" ${settings.chat_background === 'gradient2' ? 'selected' : ''}>Purple Gradient</option>
                    <option value="solid" data-i18n="settings.solid_color" ${settings.chat_background === 'solid' ? 'selected' : ''}>Solid Color</option>
                </select>
            </div>
        </div>
    `;
    }

    function getStorageSettingsHTML() {
        const settings = window.userSettings || {};

        return `
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-hdd"></i>
                Storage Usage
            </div>
            
            <div class="settings-option" id="storageUsageSummary" aria-live="polite">
                <div class="storage-info">
                    <span>Messages</span>
                    <span>Loading...</span>
                </div>
                <div class="storage-info">
                    <span>Media</span>
                    <span>Loading...</span>
                </div>
                <div class="storage-info">
                    <span>Documents</span>
                    <span>Loading...</span>
                </div>
                <div class="storage-info">
                    <span><strong>Total</strong></span>
                    <span><strong>Loading...</strong></span>
                </div>
            </div>
            
            <button class="settings-button" data-pm-action="clear-cache">
                <i class="fas fa-broom me-2"></i>Clear Cache
            </button>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-download"></i>
                Auto-Download
            </div>
            
            <div class="settings-option">
                <div class="settings-option-info">
                    <div class="settings-option-title">Auto-Download Media</div>
                    <div class="settings-option-description">Automatically download photos and videos</div>
                </div>
                <label class="settings-toggle">
                    <input type="checkbox" id="autoDownload" aria-label="Auto-download media" ${settings.auto_download ? 'checked' : ''}
                           data-pm-action="update-setting" data-pm-setting="auto_download">
                    <span class="settings-slider"></span>
                </label>
            </div>
        </div>
    `;
    }

    function getAboutSettingsHTML() {
        return `
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-info-circle"></i>
                Application Info
            </div>
            
            <div class="version-info">
                <div><strong>Messenger</strong></div>
                <div>Version 1.0.0</div>
                <div>Build 2024.01.15</div>
                <div class="about-copyright">
                    © 2024 Messenger. All rights reserved.
                </div>
            </div>
        </div>
        
        <div class="settings-section">
            <div class="settings-section-title">
                <i class="fas fa-question-circle"></i>
                Support
            </div>
            
            <button class="settings-button" data-pm-action="toast" data-pm-toast-key="about.support_soon">
                <i class="fas fa-envelope me-2"></i>Contact Support
            </button>
            
            <button class="settings-button" data-pm-action="toast" data-pm-toast-key="about.help_soon">
                <i class="fas fa-book me-2"></i>Help Center
            </button>
            
            <button class="settings-button" data-pm-action="toast" data-pm-toast-key="about.legal_soon">
                <i class="fas fa-file-contract me-2"></i>Terms & Privacy
            </button>
        </div>
    `;
    }

    // Settings action functions
    function loadUserProfile() {
        if (!currentUser) return false;
        const firstNameField = document.getElementById('profileFirstName');
        const lastNameField = document.getElementById('profileLastName');
        const usernameField = document.getElementById('profileUsername');
        const bioField = document.getElementById('profileBio');
        const profileName = document.getElementById('profileNameLarge');
        const profileUsername = document.getElementById('profileUsernameLarge');
        const avatarLarge = document.getElementById('profileAvatarLarge');
        // An avatar scan may finish after Settings has been closed. Updating the
        // persistent currentUser object is still useful, but detached profile
        // controls must not turn a successful upload into a client exception.
        if (!firstNameField || !lastNameField || !usernameField || !bioField ||
            !profileName || !profileUsername || !avatarLarge) {
            return false;
        }

        // Load user data into profile form
        firstNameField.value = currentUser.first_name || '';
        lastNameField.value = currentUser.last_name || '';
        usernameField.value = currentUser.username || '';
        bioField.value = currentUser.bio || '';

        // Check if phone field exists before trying to set it
        const phoneField = document.getElementById('profilePhone');
        if (phoneField) {
            phoneField.value = currentUser.phone || '';
        }

        // Update large profile display
        profileName.textContent = (currentUser.first_name + ' ' + currentUser.last_name).trim();
        profileUsername.textContent = '@' + (currentUser.username || 'username');

        if (currentUser.avatar) {
            avatarLarge.innerHTML = `
            <img src="${currentUser.avatar}" alt="Profile avatar" class="avatar-image-fill">
            <div class="avatar-upload-overlay">
                <i class="fas fa-camera"></i>
            </div>
        `;
        } else {
            avatarLarge.innerHTML = `
            ${(currentUser.first_name || 'U').charAt(0).toUpperCase()}
            <div class="avatar-upload-overlay">
                <i class="fas fa-camera"></i>
                </div>
            `;
        }
        return true;
    }

    function updateProfile() {
        const firstName = document.getElementById('profileFirstName').value.trim();
        const lastName = document.getElementById('profileLastName').value.trim();
        const username = document.getElementById('profileUsername').value.trim();
        const bio = document.getElementById('profileBio').value.trim();
        const phone = document.getElementById('profilePhone') ? document.getElementById('profilePhone').value.trim() : '';

        if (!firstName || !lastName) {
            showToast('First name and last name are required', 'error');
            return;
        }

        if (firstName.length < 2 || lastName.length < 2 || firstName.length > 50 || lastName.length > 50) {
            showToast('First name and last name must be 2–50 characters long', 'error');
            return;
        }

        if (!/^[\p{L}\p{N}_.-]{3,50}$/u.test(username)) {
            showToast('Username must be 3–50 letters, numbers, dots, dashes, or underscores', 'error');
            return;
        }

        if (bio.length > 1000) {
            showToast('Bio must be 1,000 characters or fewer', 'error');
            return;
        }

        if (phone && !/^\+?[0-9 ()-]{3,20}$/.test(phone)) {
            showToast('Enter a valid phone number', 'error');
            return;
        }

        showToast('Updating profile...', 'info');

        // Check if there's an avatar file to upload
        const avatarInput = document.getElementById('avatarUploadInput');
        const hasNewAvatar = avatarInput && avatarInput.files && avatarInput.files.length > 0;

        if (hasNewAvatar) {
            // Use FormData for file upload
            const formData = new FormData();
            formData.append('action', 'update_profile');
            formData.append('first_name', firstName);
            formData.append('last_name', lastName);
            formData.append('username', username);
            formData.append('bio', bio);
            formData.append('phone', phone);
            formData.append('avatar', avatarInput.files[0]);

            fetch('api/profile.php', {
                method: 'POST',
                credentials: 'include',
                body: formData
            })
                .then(response => response.json())
                .then(handleProfileUpdateResponse)
                .catch(handleProfileUpdateError);
        } else {
            // Use JSON for text-only update
            fetch('api/settings.php', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                credentials: 'include',
                body: JSON.stringify({
                    action: 'update_profile',
                    first_name: firstName,
                    last_name: lastName,
                    username: username,
                    bio: bio,
                    phone: phone
                })
            })
                .then(response => response.json())
                .then(handleProfileUpdateResponse)
                .catch(handleProfileUpdateError);
        }
    }

    function handleProfileUpdateResponse(data) {
        if (data.success) {
            showToast('Profile updated successfully!', 'success');
            // Update global user object
            currentUser = Object.assign(currentUser, data.user);
            updateUserInfo(); // Refresh sidebar
            loadUserProfile(); // Refresh profile display

            // Clear the file input
            const avatarInput = document.getElementById('avatarUploadInput');
            if (avatarInput) {
                avatarInput.value = '';
            }
        } else {
            showToast(data.message || 'Failed to update profile', 'error');
        }
    }

    function handleProfileUpdateError(error) {
        console.error('Update profile error:', error);
        showToast('Failed to update profile. Please try again.', 'error');
    }

    async function changePassword(secondFactorCode) {
        const currentPassword = document.getElementById('currentPassword').value;
        const newPassword = document.getElementById('newPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;

        if (!currentPassword || !newPassword || !confirmPassword) {
            showToast('All password fields are required', 'error');
            return;
        }

        if (newPassword !== confirmPassword) {
            showToast('New passwords do not match', 'error');
            return;
        }

        if (newPassword.length < 12 || newPassword.length > 72) {
            showToast('Password must be between 12 and 72 characters long', 'error');
            return;
        }

        if (newPassword === currentPassword) {
            showToast('New password must be different from current password', 'warning');
            return;
        }

        showToast('Changing password...', 'info');

        const passwordChange = {
            action: 'change_password',
            current_password: currentPassword,
            new_password: newPassword
        };
        if (typeof secondFactorCode === 'string' && secondFactorCode !== '') {
            passwordChange.second_factor_code = secondFactorCode;
        }

        fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify(passwordChange)
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showToast(data.message || 'Password changed successfully!', data.reauthenticate ? 'warning' : 'success');
                    // Clear password fields
                    document.getElementById('currentPassword').value = '';
                    document.getElementById('newPassword').value = '';
                    document.getElementById('confirmPassword').value = '';
                    if (data.reauthenticate) {
                        window.setTimeout(function () {
                            window.location.reload();
                        }, 1200);
                    }
                } else {
                    showToast(data.message || 'Failed to change password', 'error');
                }
            })
            .catch(error => {
                console.error('Change password error:', error);
                showToast('Failed to change password. Please try again.', 'error');
            });
    }

    async function deleteAccount() {
        const confirmed1 = await showConfirmDialog(
            'Delete Account',
            'Are you sure you want to delete your account? This action cannot be undone.',
            'Continue',
            'danger'
        );

        if (!confirmed1) return;

        const confirmed2 = await showConfirmDialog(
            'Final Confirmation',
            'This will permanently delete all your messages and data. Are you absolutely sure?',
            'Delete Account',
            'danger'
        );

        if (confirmed2) {
            showToast('🗑️ Account deletion feature coming soon!', 'info');
        }
    }

    function clearCache() {
        showLoading('Clearing cache...');

        fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'clear_cache'
            })
        })
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    showToast('🧹 Cache cleared successfully');
                } else {
                    showToast('❌ Failed to clear cache');
                }
            })
            .catch(error => {
                hideLoading();
                console.error('Clear cache error:', error);
                showToast('❌ Failed to clear cache');
            });
    }

    setInterval(() => {
        const oldToasts = document.querySelectorAll('.toast.show');
        oldToasts.forEach(toast => {
            if (toast.dataset.timestamp && Date.now() - parseInt(toast.dataset.timestamp) > 10000) {
                bootstrap.Toast.getInstance(toast)?.hide();
            }
        });
    }, 5000);

    function loadStorageUsage() {
        fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'get_storage_usage'
            })
        })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    updateStorageDisplay(data.storage);
                } else {
                    updateStorageUnavailable();
                }
            })
            .catch(error => {
                console.error('Load storage error:', error);
                updateStorageUnavailable();
            });
    }

    function updateStorageDisplay(storage) {
        const storageContainer = document.getElementById('storageUsageSummary');
        if (!storageContainer || !storage || typeof storage !== 'object') return;
        lastStorageUsage = storage;
        const byteKeys = ['messages_bytes', 'media_bytes', 'documents_bytes', 'total_bytes'];
        const legacyKeys = ['messages', 'media', 'documents', 'total'];
        const values = byteKeys.map(function (key, index) {
            const bytes = Number(storage[key]);
            if (Number.isSafeInteger(bytes) && bytes >= 0) return formatFileSize(bytes);
            const legacy = storage[legacyKeys[index]];
            return legacy === null || legacy === undefined ? translateUi('common.unavailable', {}, 'Unavailable') : String(legacy);
        });
        storageContainer.querySelectorAll(':scope > .storage-info').forEach(function (row, index) {
            const output = row.querySelector(':scope > span:last-child');
            if (!output) return;
            const value = values[index] === null || values[index] === undefined ? 'Unavailable' : String(values[index]);
            const strong = output.querySelector('strong');
            if (strong) strong.textContent = value;
            else output.textContent = value;
        });
    }

    function updateStorageUnavailable() {
        const storageContainer = document.getElementById('storageUsageSummary');
        if (!storageContainer) return;
        lastStorageUsage = null;
        storageContainer.querySelectorAll(':scope > .storage-info').forEach(function (row) {
            const output = row.querySelector(':scope > span:last-child');
            if (!output) return;
            const strong = output.querySelector('strong');
            if (strong) strong.textContent = 'Unavailable';
            else output.textContent = 'Unavailable';
        });
    }

    function refreshLocalizedStorageUsage() {
        if (lastStorageUsage) updateStorageDisplay(lastStorageUsage);
    }

    // 2FA Functions
    function toggle2FA(enabled) {
        if (enabled) {
            setup2FA();
        } else {
            disable2FA();
        }
    }

    function setup2FA() {
        showLoading('Setting up 2FA...');

        fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'setup_2fa'
            })
        })
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    show2FASetupModal(data);
                } else {
                    showToast('❌ Failed to setup 2FA');
                    document.getElementById('twoFactorToggle').checked = false;
                }
            })
            .catch(error => {
                hideLoading();
                console.error('Setup 2FA error:', error);
                showToast('❌ Failed to setup 2FA');
                document.getElementById('twoFactorToggle').checked = false;
            });
    }

    function show2FASetupModal(data) {
        let qrSection = '';
        const secret = typeof data.secret === 'string' && /^[A-Z2-7]{16,64}$/.test(data.secret)
            ? data.secret
            : '';
        const manualEntryKey = typeof data.manual_entry_key === 'string' &&
            /^[A-Z2-7 ]{16,96}$/.test(data.manual_entry_key)
            ? data.manual_entry_key
            : '';
        const account = escapeHtml(String(data.account || ''));
        const issuer = escapeHtml(String(data.issuer || 'Messenger'));
        const safeManualEntryKey = escapeHtml(manualEntryKey);
        const qrCode = data.qr_available && typeof data.qr_code === 'string' &&
            data.qr_code.length <= 2 * 1024 * 1024 &&
            /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(data.qr_code)
            ? data.qr_code
            : '';

        if (!secret || !manualEntryKey) {
            showToast('❌ Invalid 2FA setup response', 'error');
            const toggle = document.getElementById('twoFactorToggle');
            if (toggle) toggle.checked = false;
            return;
        }

        if (qrCode) {
            qrSection = `
            <div class="text-center mb-4">
                <h6>Scan QR Code with your authenticator app</h6>
                <img src="${qrCode}" alt="QR Code" class="img-fluid mb-3 two-factor-qr">
            </div>
        `;
        } else {
            qrSection = `
            <div class="alert alert-info mb-4">
                <i class="fas fa-info-circle me-2"></i>
                QR code not available. Please set up manually using the details below.
            </div>
        `;
        }

        const modalHTML = `
        <div class="modal fade" id="setup2FAModal" tabindex="-1" role="dialog" aria-modal="true" aria-labelledby="setup2FAModalTitle">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="setup2FAModalTitle">Setup Two-Factor Authentication</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        ${qrSection}
                        
                        <div class="mb-4">
                            <h6>Manual Setup</h6>
                            <div class="alert alert-secondary">
                                <strong>Account:</strong> <bdi dir="auto" data-i18n-ignore>${account}</bdi><br>
                                <strong>Issuer:</strong> <bdi dir="auto" data-i18n-ignore>${issuer}</bdi><br>
                                <strong>Secret Key:</strong> <code dir="ltr" class="two-factor-secret" data-i18n-ignore>${safeManualEntryKey}</code>
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label for="verify2FACode" class="form-label">Enter verification code</label>
                            <input type="text" class="form-control" id="verify2FACode" placeholder="Enter 6-digit code" maxlength="6"
                                   inputmode="numeric" autocomplete="one-time-code">
                        </div>
                        
                        <div class="alert alert-info">
                            <i class="fas fa-info-circle me-2"></i>
                            <strong>Recommended apps:</strong><br>
                            • Google Authenticator<br>
                            • Microsoft Authenticator<br>
                            • Authy<br>
                            • 1Password<br>
                            • Bitwarden
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal" data-pm-action="cancel-2fa-setup">Cancel</button>
                        <button type="button" class="btn btn-primary" data-pm-action="verify-2fa-setup" data-pm-secret="${secret}">Verify & Enable</button>
                    </div>
                </div>
            </div>
        </div>
    `;

        // Remove existing modal if any
        const existingModal = document.getElementById('setup2FAModal');
        if (existingModal) {
            bootstrap.Modal.getInstance(existingModal)?.dispose();
            existingModal.remove();
        }

        document.body.insertAdjacentHTML('beforeend', modalHTML);
        const setupModalElement = document.getElementById('setup2FAModal');
        const setupModal = new bootstrap.Modal(setupModalElement);
        setupModalElement.addEventListener('shown.bs.modal', function () {
            setupModalElement.querySelector('#verify2FACode')?.focus({preventScroll: true});
        }, {once: true});
        setupModalElement.addEventListener('hidden.bs.modal', function () {
            setupModalElement.querySelectorAll('[data-pm-secret]').forEach(function (element) {
                element.removeAttribute('data-pm-secret');
            });
            const codeInput = setupModalElement.querySelector('#verify2FACode');
            if (codeInput) codeInput.value = '';
            setupModal.dispose();
            setupModalElement.remove();
            if (!window.userSettings || !window.userSettings.two_factor_enabled) {
                const toggle = document.getElementById('twoFactorToggle');
                if (toggle) toggle.checked = false;
            }
        }, {once: true});
        setupModal.show();
    }

    function verify2FASetup(secret) {
        const code = document.getElementById('verify2FACode').value.trim();

        if (!code) {
            showToast('❌ Please enter a verification code');
            return;
        }

        if (!/^\d{6}$/.test(code)) {
            showToast('❌ Please enter a valid 6-digit code');
            return;
        }

        showLoading('Verifying code...');

        fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'verify_2fa_setup',
                secret: secret,
                code: code
            })
        })
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    // Update settings and refresh UI
                    window.userSettings = window.userSettings || {};
                    window.userSettings.two_factor_enabled = true;
                    const setupModalElement = document.getElementById('setup2FAModal');
                    const setupModal = setupModalElement && bootstrap.Modal.getInstance(setupModalElement);
                    const recoveryCodes = Array.isArray(data.backup_codes) ? data.backup_codes.slice() : [];
                    if (Array.isArray(data.backup_codes)) data.backup_codes.fill('');
                    const showRecoveryCodes = function () {
                        showBackupCodes(recoveryCodes);
                        if (!data.reauthenticate) return;

                        // Keep the one-time codes visible until the user has
                        // saved them, then force the now-required sign-in.
                        const backupModalElement = document.getElementById('backupCodesModal');
                        if (backupModalElement) {
                            backupModalElement.addEventListener('hidden.bs.modal', function () {
                                window.location.reload();
                            }, {once: true});
                        } else {
                            window.setTimeout(function () {
                                window.location.reload();
                            }, 1200);
                        }
                    };
                    if (setupModalElement && setupModal) {
                        setupModalElement.addEventListener('hidden.bs.modal', showRecoveryCodes, {once: true});
                        setupModal.hide();
                    } else {
                        showRecoveryCodes();
                    }
                    showToast(
                        data.message || '2FA enabled successfully!',
                        data.reauthenticate ? 'warning' : 'success'
                    );
                    showSettingsSection('account');
                } else {
                    const message = data.message
                        ? translateUiText(data.message)
                        : translateUi('api.invalid_verification', {}, 'Invalid verification code');
                    showToast('❌ ' + message);
                    document.getElementById('verify2FACode').focus();
                }
            })
            .catch(error => {
                hideLoading();
                console.error('Verify 2FA error:', error);
                showToast('❌ Network error. Please try again.');
            });
    }

    function cancel2FASetup() {
        document.getElementById('twoFactorToggle').checked = false;
    }

    function disable2FA() {
        const code = prompt('Enter your 2FA code or backup code to disable 2FA:');

        if (!code) {
            document.getElementById('twoFactorToggle').checked = true;
            return;
        }

        showLoading('Disabling 2FA...');

        fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'disable_2fa',
                code: code
            })
        })
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    showToast('✅ 2FA disabled successfully');
                    window.userSettings.two_factor_enabled = false;
                    showSettingsSection('account');
                } else {
                    const message = data.message
                        ? translateUiText(data.message)
                        : translateUi('api.invalid_verification', {}, 'Invalid verification code');
                    showToast('❌ ' + message);
                    document.getElementById('twoFactorToggle').checked = true;
                }
            })
            .catch(error => {
                hideLoading();
                console.error('Disable 2FA error:', error);
                showToast('❌ Failed to disable 2FA');
                document.getElementById('twoFactorToggle').checked = true;
            });
    }

    function generateBackupCodes() {
        showLoading('Generating backup codes...');

        fetch('api/settings.php', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                action: 'get_backup_codes'
            })
        })
            .then(response => response.json())
            .then(data => {
                hideLoading();
                if (data.success) {
                    showBackupCodes(data.backup_codes);
                } else {
                    showToast('❌ Failed to generate backup codes');
                }
            })
            .catch(error => {
                hideLoading();
                console.error('Generate backup codes error:', error);
                showToast('❌ Failed to generate backup codes');
            });
    }

    function showBackupCodes(codes) {
        const existingModal = document.getElementById('backupCodesModal');
        if (existingModal) {
            bootstrap.Modal.getInstance(existingModal)?.dispose();
            existingModal.remove();
        }
        if (Array.isArray(window.currentBackupCodes)) {
            window.currentBackupCodes.fill('');
        }
        delete window.currentBackupCodes;
        const displayCodes = Array.isArray(codes)
            ? codes.map(code => String(code).toUpperCase()).filter(code => /^[A-F0-9]{8}$/.test(code))
            : [];
        if (displayCodes.length === 0) {
            showToast('❌ No valid backup codes were returned', 'error');
            if (Array.isArray(codes)) codes.fill('');
            return;
        }
        const modalHTML = `
        <div class="modal fade" id="backupCodesModal" tabindex="-1" role="dialog" aria-modal="true" aria-labelledby="backupCodesModalTitle">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="backupCodesModalTitle" tabindex="-1">Backup Codes</h5>
                        <button type="button" class="btn-close btn-close-white" data-bs-dismiss="modal" aria-label="Close"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-warning">
                            <i class="fas fa-exclamation-triangle me-2"></i>
                            Save these backup codes in a safe place. Each code can only be used once.
                        </div>
                        
                        <div class="backup-codes">
                            ${displayCodes.map(code => `<div class="mb-1" dir="ltr" data-i18n-ignore>${code}</div>`).join('')}
                        </div>
                        
                        <div class="mt-3">
                            <button class="btn btn-outline-primary" data-pm-action="copy-backup-codes">
                                <i class="fas fa-copy me-2"></i>Copy Codes
                            </button>
                            <button class="btn btn-outline-secondary ms-2" data-pm-action="download-backup-codes">
                                <i class="fas fa-download me-2"></i>Download
                            </button>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button type="button" class="btn btn-primary" data-bs-dismiss="modal">I've Saved These Codes</button>
                    </div>
                </div>
            </div>
        </div>
    `;

        // Store codes for copy/download functions
        window.currentBackupCodes = displayCodes;

        document.body.insertAdjacentHTML('beforeend', modalHTML);
        const backupModalElement = document.getElementById('backupCodesModal');
        const backupModal = new bootstrap.Modal(backupModalElement);
        backupModalElement.addEventListener('shown.bs.modal', function () {
            backupModalElement.querySelector('#backupCodesModalTitle')?.focus({preventScroll: true});
        }, {once: true});
        backupModalElement.addEventListener('hidden.bs.modal', function () {
            displayCodes.fill('');
            if (Array.isArray(codes)) codes.fill('');
            if (Array.isArray(window.currentBackupCodes)) window.currentBackupCodes.fill('');
            delete window.currentBackupCodes;
            backupModalElement.querySelector('.backup-codes')?.replaceChildren();
            backupModal.dispose();
            backupModalElement.remove();
        }, {once: true});
        backupModal.show();
    }

    function copyBackupCodes() {
        if (!Array.isArray(window.currentBackupCodes)) return;
        const codes = window.currentBackupCodes.join('\n');
        navigator.clipboard.writeText(codes).then(() => {
            showToast('📋 Backup codes copied to clipboard');
        });
    }

    function downloadBackupCodes() {
        if (!Array.isArray(window.currentBackupCodes)) return;
        const codes = window.currentBackupCodes.join('\n');
        const blob = new Blob([codes], {type: 'text/plain'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'messenger-backup-codes.txt';
        a.click();
        URL.revokeObjectURL(url);
        showToast('💾 Backup codes downloaded');
    }

    function showToast(message, type = 'info', duration = 5000) {
        message = translateUiText(message);
        const toastEl = document.getElementById('mainToast');
        if (!toastEl) {
            console.error('Toast element not found');
            // Fallback to alert if toast is not available
            alert(message);
            return;
        }

        // Set toast content
        const titleEl = toastEl.querySelector('.toast-title');
        const bodyEl = toastEl.querySelector('.toast-body');
        const iconEl = toastEl.querySelector('.toast-icon');

        // Check if elements exist before trying to modify them
        if (!titleEl || !bodyEl || !iconEl) {
            console.error('Toast elements not found:', {titleEl, bodyEl, iconEl});
            // Fallback to alert if toast elements are missing
            alert(message);
            return;
        }

        // Set icon and styling based on type
        let icon, title;
        switch (type) {
            case 'success':
                icon = 'fas fa-check-circle text-success';
                title = 'Success';
                break;
            case 'error':
                icon = 'fas fa-exclamation-circle text-danger';
                title = 'Error';
                break;
            case 'warning':
                icon = 'fas fa-exclamation-triangle text-warning';
                title = 'Warning';
                break;
            case 'info':
            default:
                icon = 'fas fa-info-circle text-info';
                title = 'Info';
                break;
        }
        title = translateUiText(title);

        // Update the icon classes
        iconEl.className = `toast-icon me-2 ${icon}`;
        titleEl.textContent = title;
        bodyEl.textContent = message;

        // Create and show toast
        const toast = new bootstrap.Toast(toastEl, {
            autohide: true,
            delay: duration
        });

        toast.show();
    }

    // Graceful Confirmation Dialog
    function showConfirmDialog(title, message, confirmText = 'Confirm', type = 'primary') {
        title = translateUiText(title);
        message = translateUiText(message);
        confirmText = translateUiText(confirmText);
        return new Promise((resolve) => {
            const modal = document.getElementById('confirmModal');
            if (!modal) {
                console.error('Confirm modal not found');
                resolve(confirm(message)); // Fallback to browser confirm
                return;
            }

            const titleEl = modal.querySelector('.confirm-title');
            const messageEl = modal.querySelector('.confirm-message');
            const iconEl = modal.querySelector('.confirm-icon');
            const confirmBtn = modal.querySelector('#confirmActionBtn');

            // Check if elements exist
            if (!titleEl || !messageEl || !iconEl || !confirmBtn) {
                console.error('Confirm modal elements not found:', {titleEl, messageEl, iconEl, confirmBtn});
                resolve(confirm(message)); // Fallback to browser confirm
                return;
            }

            // Set content
            titleEl.textContent = title;
            messageEl.textContent = message;
            confirmBtn.textContent = confirmText;

            // Set icon and button style
            let icon;
            switch (type) {
                case 'danger':
                    icon = 'fas fa-exclamation-triangle text-danger';
                    confirmBtn.className = 'btn btn-danger';
                    break;
                case 'warning':
                    icon = 'fas fa-exclamation-circle text-warning';
                    confirmBtn.className = 'btn btn-warning';
                    break;
                default:
                    icon = 'fas fa-question-circle text-primary';
                    confirmBtn.className = 'btn btn-primary';
                    break;
            }
            iconEl.className = `confirm-icon me-2 ${icon}`;

            // Handle confirmation
            const handleConfirm = () => {
                confirmBtn.removeEventListener('click', handleConfirm);
                bootstrap.Modal.getInstance(modal).hide();
                resolve(true);
            };

            const handleCancel = () => {
                modal.removeEventListener('hidden.bs.modal', handleCancel);
                resolve(false);
            };

            confirmBtn.addEventListener('click', handleConfirm);
            modal.addEventListener('hidden.bs.modal', handleCancel, {once: true});

            // Show modal
            new bootstrap.Modal(modal).show();
        });
    }

    // Show/Hide button loading state
    function setButtonLoading(buttonId, loading = true) {
        const btn = document.getElementById(buttonId);
        const textEl = btn.querySelector('.btn-text');
        const spinnerEl = btn.querySelector('.btn-spinner');

        if (loading) {
            textEl.classList.add('d-none');
            spinnerEl.classList.remove('d-none');
            btn.disabled = true;
        } else {
            textEl.classList.remove('d-none');
            spinnerEl.classList.add('d-none');
            btn.disabled = false;
        }
    }

    // Loading overlay functions
    function showLoading(message) {
        message = translateUiText(message || 'Loading...');
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.querySelector('.loading-spinner div').textContent = message;
            overlay.style.display = 'flex';
        }
    }

    function hideLoading() {
        const overlay = document.getElementById('loadingOverlay');
        if (overlay) {
            overlay.style.display = 'none';
        }
    }

    // Keyboard shortcuts
    document.addEventListener('keydown', function (e) {
        // Ctrl/Cmd + K to search
        if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
            e.preventDefault();
            document.getElementById('searchInput').focus();
        }

        // Ctrl/Cmd + N for new chat
        if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
            e.preventDefault();
            showNewChatModal();
        }

        // Escape to close modals
        if (e.key === 'Escape') {
            const modals = document.querySelectorAll('.modal.show');
            modals.forEach(function (modal) {
                const instance = bootstrap.Modal.getInstance(modal);
                if (instance) {
                    instance.hide();
                }
            });

            // Close context menu
            hideContextMenu();

            // Clear reply
            clearReply();
        }
    });

    // Utility functions
    function parseServerTimestamp(timestamp) {
        if (timestamp instanceof Date) {
            return Number.isNaN(timestamp.getTime()) ? null : new Date(timestamp.getTime());
        }
        if (typeof timestamp === 'number' && Number.isFinite(timestamp)) {
            const numericDate = new Date(timestamp);
            return Number.isNaN(numericDate.getTime()) ? null : numericDate;
        }

        const value = String(timestamp || '').trim();
        if (!value) return null;
        const mysqlUtc = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2}:\d{2})(?:\.(\d{1,6}))?$/.exec(value);
        const normalized = mysqlUtc
            ? mysqlUtc[1] + 'T' + mysqlUtc[2] + (mysqlUtc[3] ? '.' + mysqlUtc[3].slice(0, 3).padEnd(3, '0') : '') + 'Z'
            : value;
        const date = new Date(normalized);
        return Number.isNaN(date.getTime()) ? null : date;
    }

    window.parsePmTimestamp = parseServerTimestamp;

    function formatTime(timestamp) {
        const date = parseServerTimestamp(timestamp);
        if (!date) return '';
        const now = new Date();
        const diffInHours = (now - date) / (1000 * 60 * 60);
        const i18n = window.PmI18n;

        if (diffInHours < 24) {
            return i18n && typeof i18n.formatTime === 'function'
                ? i18n.formatTime(date, {hour: '2-digit', minute: '2-digit'})
                : date.toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
        } else if (diffInHours < 168) { // Less than a week
            return i18n && typeof i18n.formatDate === 'function'
                ? i18n.formatDate(date, {weekday: 'short'})
                : date.toLocaleDateString([], {weekday: 'short'});
        } else {
            return i18n && typeof i18n.formatDate === 'function'
                ? i18n.formatDate(date, {month: 'short', day: 'numeric'})
                : date.toLocaleDateString([], {month: 'short', day: 'numeric'});
        }
    }

    window.setAppLocale = function setAppLocale(locale) {
        if (!window.PmI18n || typeof window.PmI18n.setLocale !== 'function') return Promise.resolve(false);
        return Promise.resolve(window.PmI18n.setLocale(locale)).then(function () {
            showToast(translateUi('settings.language.changed', {}, 'Language updated'), 'success', 2400);
            return true;
        }).catch(function (error) {
            console.error('Locale update error:', error);
            showToast(translateUi('settings.language.failed', {}, 'Language could not be changed'), 'error');
            return false;
        });
    };

    function refreshLocalizedTimestamps() {
        document.querySelectorAll('#chatList .chat-item').forEach(function (row) {
            const refs = row.__pmChatRefs;
            const chat = row.__pmChatData;
            if (refs && refs.time && chat) {
                refs.time.textContent = chat.last_message_time ? formatTime(chat.last_message_time) : '';
            }
        });
        document.querySelectorAll('#messagesList .message[data-created-at]').forEach(function (row) {
            const output = row.querySelector('.message-time');
            if (output) output.textContent = formatTime(row.dataset.createdAt);
        });
        document.querySelectorAll('[data-i18n-number]').forEach(function (output) {
            const value = Number(output.dataset.i18nNumber);
            if (Number.isSafeInteger(value) && value >= 0) output.textContent = formatUiNumber(value);
        });
        if (currentChatInfo && currentChatInfo.other_user) {
            const online = currentChatInfo.other_user.is_online == 1 || currentChatInfo.other_user.is_online === true;
            const status = document.getElementById('chatStatus');
            if (status) {
                status.textContent = online
                    ? translateUi('chat.online', {}, 'Online')
                    : translateUi('chat.last_seen', {time: formatTime(currentChatInfo.other_user.last_seen)},
                        'Last seen ' + formatTime(currentChatInfo.other_user.last_seen));
            }
        }
    }

    function refreshLocalizedApplicationChrome() {
        refreshLocalizedTimestamps();
        refreshLocalizedStorageUsage();
        refreshReplyComposerSender();
        if (typeof window.refreshLocalizedSecurityChrome === 'function') window.refreshLocalizedSecurityChrome();
        if (typeof window.refreshConversationRowStates === 'function') window.refreshConversationRowStates();
        if (typeof window.refreshLocalizedChatUx === 'function') window.refreshLocalizedChatUx();
        if (typeof window.refreshLocalizedAccessibility === 'function') window.refreshLocalizedAccessibility();
    }

    window.addEventListener('pm:localechange', refreshLocalizedApplicationChrome);
    if (window.PmI18n && window.PmI18n.ready && typeof window.PmI18n.ready.then === 'function') {
        window.PmI18n.ready.then(function () {
            window.setTimeout(refreshLocalizedApplicationChrome, 0);
        }).catch(function () {});
    }

    function escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    function toggleSidebar() {
        document.getElementById('sidebar').classList.toggle('show');
    }


    // Mobile sidebar functions
    function showMobileSidebar() {
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.add('show');
            document.getElementById('sidebarOverlay').classList.add('show');
            document.body.style.overflow = 'hidden'; // Prevent background scrolling
        }
    }

    function hideMobileSidebar() {
        document.getElementById('sidebar').classList.remove('show');
        document.getElementById('sidebarOverlay').classList.remove('show');
        document.body.style.overflow = ''; // Restore scrolling
    }

    // Update the existing toggleSidebar function
    function toggleSidebar() {
        if (window.innerWidth <= 768) {
            const sidebar = document.getElementById('sidebar');
            if (sidebar.classList.contains('show')) {
                hideMobileSidebar();
            } else {
                showMobileSidebar();
            }
        }
    }

    function selectChat(chatId, chatInfo) {
        if (String(chatId) !== String(currentChatId)) markClientSendSemanticsChanged();
        currentChatId = chatId;
        currentChatInfo = chatInfo;
        lastMessageId = null;
        hasMoreMessages = true;
        isInitialLoad = true;

        // Update UI
        document.querySelectorAll('.chat-item').forEach(function (item) {
            item.classList.remove('active');
        });
        event.currentTarget.classList.add('active');

        // Hide welcome screen and show chat content
        document.getElementById('welcomeScreen').classList.add('d-none');
        document.getElementById('chatContent').classList.remove('d-none');

        // Update chat header
        document.getElementById('chatTitle').textContent = chatInfo.title || 'Unknown';

        if (chatInfo.other_user) {
            // Use REAL online status from server data
            const isReallyOnline = chatInfo.other_user.is_online == 1 || chatInfo.other_user.is_online === true;
            const lastSeen = formatTime(chatInfo.other_user.last_seen);
            const status = isReallyOnline
                ? translateUi('chat.online', {}, 'Online')
                : translateUi('chat.last_seen', {time: lastSeen}, 'Last seen ' + lastSeen);

            document.getElementById('chatStatus').textContent = status;
            document.getElementById('chatStatus').className = isReallyOnline ? 'chat-status online' : 'chat-status';

            if (isReallyOnline) {
                document.getElementById('onlineIndicator').classList.remove('d-none');
            } else {
                document.getElementById('onlineIndicator').classList.add('d-none');
            }
        }

        const avatar = chatInfo.chat_avatar ?
            '<img src="' + chatInfo.chat_avatar + '" alt="Avatar" class="avatar-image-fill">' :
            (chatInfo.title ? chatInfo.title.charAt(0).toUpperCase() : 'C');
        document.getElementById('chatAvatar').innerHTML = avatar;

        // Load messages
        loadMessages(chatId);

        // Hide sidebar on mobile when chat is selected
        if (window.innerWidth <= 768) {
            hideMobileSidebar(); // This properly hides sidebar and overlay
            // Hide bottom navigation when inside a chat
            hideBottomNav();
        }
    }

    // Handle window resize
    window.addEventListener('resize', function () {
        if (window.innerWidth > 768) {
            // On desktop, ensure sidebar is visible and overlay is hidden
            document.getElementById('sidebar').classList.remove('show');
            document.getElementById('sidebarOverlay').classList.remove('show');
            document.body.style.overflow = '';

            // Show welcome screen if no chat is selected
            if (!currentChatId) {
                document.getElementById('welcomeScreen').classList.remove('d-none');
                document.getElementById('chatContent').classList.add('d-none');
            }
        } else {
            // On mobile, if no chat is selected, show sidebar
            if (!currentChatId) {
                showMobileSidebar();
                document.getElementById('welcomeScreen').classList.add('d-none');
                document.getElementById('chatContent').classList.add('d-none');
            }
        }
    });

    // Handle escape key to close mobile sidebar
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            if (window.innerWidth <= 768) {
                hideMobileSidebar();
            }

            // Other escape key handlers...
            const modals = document.querySelectorAll('.modal.show');
            modals.forEach(function (modal) {
                const instance = bootstrap.Modal.getInstance(modal);
                if (instance) {
                    instance.hide();
                }
            });

            hideContextMenu();
            clearReply();
        }
    });

    // Enhanced new chat modal show function
    function showNewChatModal() {
        // Hide mobile sidebar if open
        if (window.innerWidth <= 768) {
            hideMobileSidebar();
        }
        new bootstrap.Modal(document.getElementById('newChatModal')).show();
    }

    function backToChats() {
        // Check if we're currently in a settings section (settings content is visible)
        const settingsContent = document.getElementById('settingsContent');
        const settingsList = document.getElementById('settingsList');
        const chatList = document.getElementById('chatList');

        if (!settingsContent.classList.contains('d-none')) {
            // We're in a settings section, go back to settings list
            settingsContent.classList.add('d-none');

            // On mobile, show settings list; on desktop, keep both visible
            if (window.innerWidth <= 768) {
                settingsList.classList.remove('d-none');
                showMobileSidebar();
            }

            // Update search placeholder back to settings
            document.getElementById('searchInput').placeholder = 'Search settings...';

            showToast('⚙️ Back to settings');
            return;
        }

        // We're in settings list, go back to chats
        chatList.classList.remove('d-none');
        settingsList.classList.add('d-none');

        // Hide settings content, show welcome or current chat
        settingsContent.classList.add('d-none');
        if (currentChatId) {
            document.getElementById('chatContent').classList.remove('d-none');
        } else {
            if (window.innerWidth > 768) {
                // Desktop: show welcome screen
                document.getElementById('welcomeScreen').classList.remove('d-none');
            } else {
                // Mobile: show sidebar with chats
                showMobileSidebar();
                document.getElementById('welcomeScreen').classList.add('d-none');
                // Update bottom nav to chats
                updateBottomNavActive('chats');
            }
        }

        // Update search placeholder
        document.getElementById('searchInput').placeholder = 'Search chats...';

        showToast('💬 Back to chats');
    }

    // Mobile bottom navigation functions
    function showChatsTab() {
        // Update active tab
        updateBottomNavActive('chats');

        // Show chat list
        document.getElementById('chatList').classList.remove('d-none');
        document.getElementById('settingsList').classList.add('d-none');
        document.getElementById('settingsContent').classList.add('d-none');

        // Force show sidebar without overlay (don't use showMobileSidebar)
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.add('show');
            // Don't show overlay for bottom nav interactions
            document.getElementById('sidebarOverlay').classList.remove('show');
            document.body.style.overflow = ''; // Allow scrolling
        }

        // Show bottom nav
        showBottomNav();

        // Hide chat content if no chat selected
        if (!currentChatId) {
            document.getElementById('chatContent').classList.add('d-none');
            document.getElementById('welcomeScreen').classList.add('d-none');
        }

        // Update search placeholder
        document.getElementById('searchInput').placeholder = 'Search chats...';
    }

    function showExploreTab() {
        // Update active tab
        updateBottomNavActive('explore');

        // Hide sidebar and show explore content (for now just show new chat modal)
        hideMobileSidebar();
        showNewChatModal();

        // Reset to chats tab after modal
        setTimeout(() => {
            updateBottomNavActive('chats');
        }, 100);
    }

    function showMeTab() {
        // Update active tab
        updateBottomNavActive('me');

        // Show settings
        document.getElementById('chatList').classList.add('d-none');
        document.getElementById('settingsList').classList.remove('d-none');
        document.getElementById('settingsContent').classList.add('d-none');

        // Force show sidebar without overlay (don't use showMobileSidebar)
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.add('show');
            // Don't show overlay for bottom nav interactions
            document.getElementById('sidebarOverlay').classList.remove('show');
            document.body.style.overflow = ''; // Allow scrolling
        }

        // Show bottom nav
        showBottomNav();

        // Update search placeholder
        document.getElementById('searchInput').placeholder = 'Search settings...';
    }

    function updateBottomNavActive(activeTab) {
        // Remove active class from all items
        document.querySelectorAll('.bottom-nav-item').forEach(item => {
            item.classList.remove('active');
        });

        // Add active class to selected tab
        const items = document.querySelectorAll('.bottom-nav-item');
        switch (activeTab) {
            case 'chats':
                if (items[0]) items[0].classList.add('active');
                break;
            case 'explore':
                if (items[1]) items[1].classList.add('active');
                break;
            case 'me':
                if (items[2]) items[2].classList.add('active');
                break;
        }
    }

    // Bottom navigation visibility functions
    function showBottomNav() {
        if (window.innerWidth <= 768) {
            const bottomNav = document.getElementById('mobileBottomNav');
            const mainContainer = document.querySelector('.main-container');

            if (bottomNav) {
                bottomNav.classList.remove('hidden');
                mainContainer.classList.remove('bottom-nav-hidden');
            }
        }
    }

    function hideBottomNav() {
        if (window.innerWidth <= 768) {
            const bottomNav = document.getElementById('mobileBottomNav');
            const mainContainer = document.querySelector('.main-container');

            if (bottomNav) {
                bottomNav.classList.add('hidden');
                mainContainer.classList.add('bottom-nav-hidden');
            }
        }
    }

    function goBackToChats() {
        if (window.innerWidth <= 768) {
            // Close current chat
            markClientSendSemanticsChanged();
            currentChatId = null;
            currentChatInfo = null;

            // Hide chat content
            document.getElementById('chatContent').classList.add('d-none');
            document.getElementById('welcomeScreen').classList.add('d-none');

            // Show chat list
            document.getElementById('chatList').classList.remove('d-none');
            document.getElementById('settingsList').classList.add('d-none');
            document.getElementById('settingsContent').classList.add('d-none');

            // Force show sidebar without overlay
            document.getElementById('sidebar').classList.add('show');
            document.getElementById('sidebarOverlay').classList.remove('show');
            document.body.style.overflow = '';

            // Show bottom navigation
            showBottomNav();

            // Update bottom nav to chats tab
            updateBottomNavActive('chats');

            // Remove active state from chat items
            document.querySelectorAll('.chat-item').forEach(function (item) {
                item.classList.remove('active');
            });

            // Update search placeholder
            document.getElementById('searchInput').placeholder = 'Search chats...';

            showToast('💬 Back to chats');
        }
    }

    function showMobileSidebarWithOverlay() {
        if (window.innerWidth <= 768) {
            document.getElementById('sidebar').classList.add('show');
            document.getElementById('sidebarOverlay').classList.add('show');
            document.body.style.overflow = 'hidden'; // Prevent background scrolling
        }
    }

    function goToProfile() {
        // Show settings first
        showSettings();

        // Then show the profile section
        setTimeout(() => {
            showSettingsSection('profile');
        }, 100);

        // On mobile, hide the bottom nav doesn't apply since we're going to settings
        // The settings will be shown with bottom nav visible
    }

    // Avatar upload functions
    function changeAvatar() {
        document.getElementById('avatarUploadInput').click();
    }

    function handleAvatarUpload(event) {
        const input = event.currentTarget || event.target;
        const file = input && input.files ? input.files[0] : null;
        if (!file) return;

        // Match the server's exact avatar MIME allow-list.
        if (!['image/jpeg', 'image/png', 'image/gif', 'image/webp'].includes(file.type)) {
            showToast('Please select a JPEG, PNG, GIF, or WebP image.', 'error');
            input.value = '';
            return;
        }

        // Validate file size (5MB max)
        if (file.size < 1 || file.size > 5 * 1024 * 1024) {
            showToast('Avatar images must be between 1 byte and 5 MB.', 'error');
            input.value = '';
            return;
        }

        // Retain the File object, but clear the control before starting work.
        // This prevents Save Profile from uploading it a second time and lets
        // the user deliberately choose the same file again after a failure.
        input.value = '';
        const selectionToken = ++avatarSelectionEpoch;
        // Keep at most the newest waiting valid selection. The active request
        // is not aborted: its server-side transaction must settle before the
        // latest selection starts, so the latest database write wins.
        pendingAvatarUpload = null;
        if (avatarPreviewObjectUrl) {
            URL.revokeObjectURL(avatarPreviewObjectUrl);
            avatarPreviewObjectUrl = null;
        }

        renderAvatarUploadPreview(file, selectionToken);

        // Upload avatar
        pendingAvatarUpload = {file: file, selectionToken: selectionToken};
        processNextAvatarUpload();
    }

    function renderAvatarUploadPreview(file, selectionToken) {
        const container = document.getElementById('profileAvatarLarge');
        if (!container || selectionToken !== avatarSelectionEpoch) return;

        const objectUrl = URL.createObjectURL(file);
        avatarPreviewObjectUrl = objectUrl;
        const image = document.createElement('img');
        image.src = objectUrl;
        image.alt = 'Profile avatar preview';
        image.className = 'avatar-image-fill';
        const releaseObjectUrl = function () {
            URL.revokeObjectURL(objectUrl);
            if (avatarPreviewObjectUrl === objectUrl) avatarPreviewObjectUrl = null;
        };
        image.addEventListener('load', releaseObjectUrl, {once: true});
        image.addEventListener('error', function () {
            releaseObjectUrl();
            if (selectionToken === avatarSelectionEpoch) loadUserProfile();
        }, {once: true});

        const overlay = document.createElement('div');
        overlay.className = 'avatar-upload-overlay';
        const icon = document.createElement('i');
        icon.className = 'fas fa-camera';
        overlay.appendChild(icon);
        container.replaceChildren(image, overlay);
    }

    function processNextAvatarUpload() {
        if (avatarUploadInFlight || pendingAvatarUpload === null) return;
        const nextUpload = pendingAvatarUpload;
        pendingAvatarUpload = null;
        avatarUploadInFlight = true;
        Promise.resolve()
            .then(function () {
                return uploadAvatar(nextUpload.file, nextUpload.selectionToken);
            })
            .catch(function (error) {
                if (nextUpload.selectionToken !== avatarSelectionEpoch) return;
                console.error('Avatar upload initialization error:', error);
                showToast('Failed to start the avatar upload. Please try again.', 'error');
                return refreshCurrentUserProfile(nextUpload.selectionToken);
            })
            .finally(function () {
                avatarUploadInFlight = false;
                processNextAvatarUpload();
            });
    }

    // Remove the getSessionToken() function call and update uploadAvatar function
    function uploadAvatar(file, selectionToken) {
        const formData = new FormData();
        formData.append('avatar', file);

        showToast('Uploading avatar...', 'info');

        const requestOptions = {
            method: 'POST',
            credentials: 'include',
            body: formData
        };

        return fetch('api/profile.php', requestOptions)
            .then(function (response) {
                return response.json().then(function (data) {
                    return {response: response, data: data};
                });
            })
            .then(result => {
                const data = result.data;
                const hasAuthoritativeUser = result.response.ok && data && data.success === true &&
                    data.user && typeof data.user === 'object' && !Array.isArray(data.user);
                // The queue is serial, so every successful response describes
                // the newest server commit observed so far. Keep that state
                // even when a newer local preview makes this response stale.
                if (hasAuthoritativeUser) {
                    currentUser = Object.assign(currentUser || {}, data.user);
                }
                if (selectionToken !== avatarSelectionEpoch) return;
                if (hasAuthoritativeUser) {
                    showToast('Avatar updated successfully!', 'success');
                    updateUserInfo();
                    loadUserProfile();
                } else {
                    showToast(data && data.message || 'Failed to upload avatar', 'error');
                    return refreshCurrentUserProfile(selectionToken);
                }
            })
            .catch(error => {
                if (selectionToken !== avatarSelectionEpoch) return;
                console.error('Avatar upload error:', error);
                showToast('Failed to upload avatar. Please try again.', 'error');
                // The request may have committed even if its response was
                // lost. Re-read authenticated server state before rendering.
                return refreshCurrentUserProfile(selectionToken);
            });
    }

    function refreshCurrentUserProfile(selectionToken) {
        return fetchWithTimeout('api/auth.php', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            credentials: 'include',
            body: JSON.stringify({action: 'validate'})
        }, AUTH_REQUEST_TIMEOUT_MS, function (response) {
            if (!response.ok) throw new Error('Profile refresh failed');
            return response.json();
        })
            .then(function (data) {
                if (!data || data.success !== true || !data.user ||
                    typeof data.user !== 'object' || Array.isArray(data.user)) {
                    throw new Error('Profile refresh returned invalid data');
                }
                currentUser = Object.assign(currentUser || {}, data.user);
                if (selectionToken === undefined || selectionToken === avatarSelectionEpoch) {
                    updateUserInfo();
                    loadUserProfile();
                }
                return true;
            })
            .catch(function (error) {
                console.error('Profile refresh error:', error);
                if (selectionToken === undefined || selectionToken === avatarSelectionEpoch) {
                    loadUserProfile();
                }
                return false;
            });
    }

    // Get session token (you may need to adjust this based on your auth system)
    function getSessionToken() {
        // If you're using session-based auth, you might not need this
        // But if you need to send a token, implement this function
        return ''; // Placeholder
    }
