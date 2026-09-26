(function () {
    'use strict';

    // The legacy bundle starts the application only after this file reaches
    // its end. Any load, parse, or initialization failure therefore leaves the
    // UI inert instead of exposing the legacy DOM-rendering fallbacks.
    window.pmSecurityHardeningReady = false;
    const requiredLegacyFunctions = [
        'updateUserInfo', 'renderChats', 'selectChat', 'renderMessages',
        'showReplyPreview', 'renderUserSearchResults', 'showChatInfo',
        'renderSearchResults', 'renderUserProfile', 'showAttachmentPreview',
        'markClientSendSemanticsChanged'
    ];
    if (!requiredLegacyFunctions.every(function (name) {
        return typeof window[name] === 'function';
    })) {
        console.error('Security hardening loaded before its required application bundle.');
        return;
    }

    const AVATAR_PATH = /^\/uploads\/avatars\/avatar_[0-9]+_[0-9]+(?:_[a-f0-9]{8})?\.(?:jpe?g|jfif|png|gif|webp)$/i;
    const AVATAR_FILE = /^avatar_[0-9]+_[0-9]+(?:_[a-f0-9]{8})?\.(?:jpe?g|jfif|png|gif|webp)$/i;
    let messageScrollRequestEpoch = 0;

    function asString(value) {
        return value === null || value === undefined ? '' : String(value);
    }

    function positiveInteger(value) {
        const number = Number(value);
        return Number.isSafeInteger(number) && number > 0 ? number : null;
    }

    function sameOriginUrl(value) {
        if (typeof value !== 'string' || value.length === 0 || value.length > 2048) {
            return null;
        }

        try {
            const url = new URL(value, document.baseURI);
            if (url.origin !== window.location.origin || !['http:', 'https:'].includes(url.protocol) || url.hash) {
                return null;
            }
            return url;
        } catch (error) {
            return null;
        }
    }

    function safeAvatarUrl(value) {
        const url = sameOriginUrl(value);
        if (!url) {
            return '';
        }

        if (AVATAR_PATH.test(url.pathname) && url.search === '') {
            const filename = url.pathname.slice(url.pathname.lastIndexOf('/') + 1);
            if (AVATAR_FILE.test(filename)) {
                return '/api/avatar.php?file=' + encodeURIComponent(filename);
            }
        }

        if (url.pathname === '/api/avatar.php' && AVATAR_FILE.test(url.searchParams.get('file') || '')) {
            const keys = Array.from(url.searchParams.keys());
            if (keys.length === 1 && keys[0] === 'file') {
                return url.pathname + '?' + url.searchParams.toString();
            }
        }

        return '';
    }

    function safeAttachmentUrl(value) {
        const url = sameOriginUrl(value);
        if (!url || url.pathname !== '/api/attachment.php') {
            return '';
        }

        const id = url.searchParams.get('id');
        if (!id || !/^[1-9][0-9]*$/.test(id)) {
            return '';
        }

        let idCount = 0;
        let retryCount = 0;
        for (const [key, parameter] of url.searchParams.entries()) {
            if (key === 'id') {
                idCount += 1;
                if (idCount !== 1 || parameter !== id) {
                    return '';
                }
                continue;
            }
            if (key !== '_retry' || ++retryCount > 1 || !/^[0-9]{1,20}$/.test(parameter)) {
                return '';
            }
        }

        if (idCount !== 1) {
            return '';
        }

        return url.pathname + '?' + url.searchParams.toString();
    }

    function appendIcon(parent, classes) {
        const icon = document.createElement('i');
        asString(classes).split(/\s+/).filter(function (name) {
            return /^(?:fa[srbld]?|fa-[a-z0-9-]+|me-[0-9]+|text-[a-z0-9-]+)$/.test(name);
        }).forEach(function (name) {
            icon.classList.add(name);
        });
        parent.appendChild(icon);
        return icon;
    }

    function initialFor(value, fallback) {
        const normalized = asString(value).trim();
        return normalized ? Array.from(normalized)[0].toUpperCase() : fallback;
    }

    function appendAvatar(container, avatarValue, name, options) {
        const avatarUrl = safeAvatarUrl(avatarValue);
        const settings = options || {};

        if (avatarUrl) {
            const image = document.createElement('img');
            image.src = avatarUrl;
            image.alt = settings.alt || 'Avatar';
            image.decoding = 'async';
            image.draggable = false;
            image.className = settings.messageAvatar ? 'message-avatar-image' : 'avatar-image-fill';
            container.appendChild(image);
            return;
        }

        if (settings.messageAvatar) {
            const fallback = document.createElement('div');
            fallback.textContent = initialFor(name, 'U');
            fallback.className = 'message-avatar-fallback';
            container.appendChild(fallback);
            return;
        }

        container.textContent = initialFor(name, 'C');
    }

    function appendTextElement(parent, tagName, className, value) {
        const element = document.createElement(tagName);
        if (className) {
            element.className = className;
        }
        element.textContent = asString(value);
        parent.appendChild(element);
        return element;
    }

    function localized(key, parameters, fallback) {
        if (window.PmI18n && typeof window.PmI18n.t === 'function') {
            const value = window.PmI18n.t(key, parameters || {});
            if (value !== key) return value;
        }
        return fallback === undefined ? key : fallback;
    }

    function localizedNumber(value) {
        return window.PmI18n && typeof window.PmI18n.formatNumber === 'function'
            ? window.PmI18n.formatNumber(value)
            : String(value);
    }

    function appendFileSize(parent, tagName, className, value) {
        const candidate = Number(value);
        const bytes = Number.isSafeInteger(candidate) && candidate >= 0 ? candidate : 0;
        const element = appendTextElement(parent, tagName, className, formatFileSize(bytes));
        element.dataset.i18nBytes = String(bytes);
        return element;
    }

    window.updateUserInfo = function secureUpdateUserInfo() {
        if (!currentUser) {
            return;
        }

        const userName = document.getElementById('userName');
        const userStatus = document.getElementById('userStatus');
        const userAvatar = document.getElementById('userAvatar');
        if (userName) {
            userName.textContent = (asString(currentUser.first_name) + ' ' + asString(currentUser.last_name)).trim();
        }
        if (userStatus) {
            userStatus.textContent = '@' + asString(currentUser.username);
        }
        if (userAvatar) {
            userAvatar.replaceChildren();
            appendAvatar(userAvatar, currentUser.avatar, currentUser.first_name, {alt: 'Your avatar'});
        }
    };

    window.renderChats = function secureRenderChats(chats) {
        const chatList = document.getElementById('chatList');
        if (!chatList) {
            return;
        }

        const normalizedChats = [];
        const seenChatIds = new Set();
        (Array.isArray(chats) ? chats : []).forEach(function (chat) {
            const chatId = positiveInteger(chat && (chat.chat_id !== undefined ? chat.chat_id : chat.id));
            if (!chatId || seenChatIds.has(chatId)) return;
            seenChatIds.add(chatId);
            normalizedChats.push({id: chatId, data: chat});
        });

        if (normalizedChats.length === 0) {
            chatList.replaceChildren();
            if (window.innerWidth <= 768) {
                const empty = document.createElement('div');
                empty.className = 'empty-chat-list';
                const icon = document.createElement('div');
                icon.className = 'empty-icon';
                appendIcon(icon, 'fas fa-comments');
                empty.appendChild(icon);
                appendTextElement(empty, 'h4', '', 'No Chats Yet');
                appendTextElement(empty, 'p', '', 'Start connecting with friends and colleagues');
                const button = document.createElement('button');
                button.type = 'button';
                button.className = 'btn btn-primary';
                appendIcon(button, 'fas fa-plus me-2');
                button.appendChild(document.createTextNode('Start New Chat'));
                button.addEventListener('click', function () {
                    window.showNewChatModal();
                });
                empty.appendChild(button);
                chatList.appendChild(empty);
            }
            return;
        }

        // Polling runs every five seconds. Reconcile by chat ID so an
        // unchanged avatar keeps the same <img> node and does not trigger a
        // fresh authenticated media request on every poll.
        const existingItems = new Map();
        Array.from(chatList.children).forEach(function (item) {
            const itemChatId = positiveInteger(item && item.dataset && item.dataset.chatId);
            if (!itemChatId || !item.__pmChatRefs || existingItems.has(itemChatId)) {
                item.remove();
                return;
            }
            existingItems.set(itemChatId, item);
        });

        normalizedChats.forEach(function (entry) {
            const chatId = entry.id;
            const chat = entry.data;
            let item = existingItems.get(chatId);
            if (!item) {
                item = document.createElement('div');
                item.className = 'chat-item';
                item.dataset.chatId = String(chatId);
                item.tabIndex = -1;
                item.setAttribute('role', 'option');
                item.setAttribute('aria-selected', 'false');
                // This row owns its keyboard activation handler. The general
                // accessibility enhancer must not install a second handler
                // that clicks the row and selects the chat twice.
                item.dataset.keyboardReady = 'true';
                item.addEventListener('click', function (event) {
                    if (item.dataset.suppressNextClick === 'true') {
                        delete item.dataset.suppressNextClick;
                        event.preventDefault();
                        event.stopPropagation();
                        return;
                    }
                    const target = event.target || event.currentTarget;
                    if (target && typeof target.closest === 'function' &&
                        target.closest('#chatRowMenu, .chat-row-menu-button')) return;
                    if (item.__pmChatData) {
                        window.selectChat(chatId, item.__pmChatData, item);
                    }
                });
                item.addEventListener('keydown', function (event) {
                    if (event.key !== 'Enter' && event.key !== ' ') return;
                    event.preventDefault();
                    // Use the same click pipeline as pointer activation so the
                    // coordinator saves the prior draft, clears attachments and
                    // reply state, and advances the request epoch exactly once.
                    item.click();
                });

                const avatar = document.createElement('div');
                avatar.className = 'chat-avatar';
                item.appendChild(avatar);

                const info = document.createElement('div');
                info.className = 'chat-info';
                const name = appendTextElement(info, 'div', 'chat-name', '');
                const lastMessage = appendTextElement(info, 'div', 'chat-last-message', '');
                name.dir = 'auto';
                name.dataset.i18nIgnore = '';
                lastMessage.dir = 'auto';
                lastMessage.dataset.i18nIgnore = '';
                item.appendChild(info);

                const meta = document.createElement('div');
                meta.className = 'chat-meta';
                const time = appendTextElement(meta, 'div', '', '');
                const delivery = appendTextElement(meta, 'span', 'chat-delivery-status', '');
                delivery.hidden = true;
                const unread = appendTextElement(meta, 'div', 'unread-count', '');
                unread.hidden = true;
                item.appendChild(meta);

                item.__pmChatRefs = {
                    avatar: avatar,
                    avatarUrl: null,
                    avatarInitial: null,
                    name: name,
                    lastMessage: lastMessage,
                    time: time,
                    delivery: delivery,
                    unread: unread
                };
            }

            existingItems.delete(chatId);
            item.__pmChatData = chat;
            const refs = item.__pmChatRefs;
            const hasTitle = chat.title !== null && chat.title !== undefined && asString(chat.title) !== '';
            const title = hasTitle ? asString(chat.title) : localized('common.unknown', {}, 'Unknown');
            const nextAvatarUrl = safeAvatarUrl(chat.chat_avatar);
            const nextAvatarInitial = initialFor(title, 'C');
            if (refs.avatarUrl !== nextAvatarUrl ||
                (!nextAvatarUrl && refs.avatarInitial !== nextAvatarInitial)) {
                refs.avatar.replaceChildren();
                appendAvatar(refs.avatar, nextAvatarUrl, title, {
                    alt: localized('files.avatar_named', {name: title}, title + ' avatar')
                });
                refs.avatarUrl = nextAvatarUrl;
                refs.avatarInitial = nextAvatarInitial;
            } else if (nextAvatarUrl && refs.avatar.childNodes[0] instanceof Element) {
                refs.avatar.childNodes[0].alt = localized('files.avatar_named', {name: title}, title + ' avatar');
            }

            refs.name.textContent = title;
            if (hasTitle) refs.name.removeAttribute('data-i18n-fallback');
            else refs.name.dataset.i18nFallback = 'common.unknown';
            const hasServerPreview = chat.last_message !== null && chat.last_message !== undefined &&
                asString(chat.last_message) !== '';
            const serverPreview = hasServerPreview ? asString(chat.last_message) : '';
            refs.lastMessage.textContent = hasServerPreview
                ? serverPreview
                : localized('chat.no_messages', {}, 'No messages yet');
            refs.time.textContent = chat.last_message_time ? formatTime(chat.last_message_time) : '';
            item.dataset.serverPreview = serverPreview;
            item.dataset.emptyPreview = hasServerPreview ? 'false' : 'true';
            item.dataset.lastMessageId = positiveInteger(chat.last_message_id) ? String(chat.last_message_id) : '';
            item.dataset.lastMessageType = asString(chat.last_message_type);
            const lastSenderId = positiveInteger(chat.last_message_sender_id !== undefined
                ? chat.last_message_sender_id
                : chat.last_sender_id);
            const lastReadCount = Number(chat.last_message_read_count !== undefined
                ? chat.last_message_read_count
                : chat.last_read_count) || 0;
            item.dataset.lastSenderId = lastSenderId ? String(lastSenderId) : '';
            item.dataset.lastReadCount = String(Math.max(0, lastReadCount));
            const ownLatestMessage = lastSenderId === positiveInteger(currentUser && currentUser.id);
            if (ownLatestMessage && positiveInteger(chat.last_message_id)) {
                const latestRead = lastReadCount > 0;
                refs.delivery.hidden = false;
                refs.delivery.textContent = latestRead ? '✓✓' : '✓';
                refs.delivery.className = 'chat-delivery-status ' + (latestRead ? 'is-read' : 'is-delivered');
                refs.delivery.setAttribute('data-i18n-aria-label', latestRead ? 'chat.read' : 'chat.delivered');
                refs.delivery.setAttribute('data-i18n-title', latestRead ? 'chat.read' : 'chat.delivered');
                refs.delivery.setAttribute('aria-label', localized(
                    latestRead ? 'chat.read' : 'chat.delivered',
                    {},
                    latestRead ? 'Read' : 'Delivered'
                ));
                refs.delivery.title = localized(
                    latestRead ? 'chat.read' : 'chat.delivered',
                    {},
                    latestRead ? 'Read' : 'Delivered'
                );
            } else {
                refs.delivery.hidden = true;
                refs.delivery.textContent = '';
                refs.delivery.removeAttribute('aria-label');
                refs.delivery.removeAttribute('title');
                refs.delivery.removeAttribute('data-i18n-aria-label');
                refs.delivery.removeAttribute('data-i18n-title');
            }
            const unread = Number(chat.unread_count);
            if (Number.isSafeInteger(unread) && unread > 0) {
                refs.unread.textContent = localizedNumber(Math.min(unread, 9999));
                refs.unread.hidden = false;
            } else {
                refs.unread.textContent = '';
                refs.unread.hidden = true;
            }

            const isActive = String(currentChatId) === String(chatId);
            item.classList.toggle('active', isActive);
            item.setAttribute('aria-label', localized('chat.open_named', {name: title}, 'Open chat: ' + title));
            item.setAttribute('aria-selected', isActive ? 'true' : 'false');
            item.removeAttribute('aria-current');
            chatList.appendChild(item);
        });

        existingItems.forEach(function (item) {
            item.remove();
        });
    };

    window.selectChat = function secureSelectChat(chatId, chatInfo, sourceElement) {
        const safeChatId = positiveInteger(chatId);
        if (!safeChatId || !chatInfo || typeof chatInfo !== 'object') {
            return;
        }

        const chatChanged = String(safeChatId) !== String(currentChatId);
        if (chatChanged) {
            markClientSendSemanticsChanged();
        }
        currentChatId = safeChatId;
        currentChatInfo = chatInfo;
        lastMessageId = null;
        hasMoreMessages = true;
        isInitialLoad = true;
        if (chatChanged) {
            messageScrollRequestEpoch += 1;
            const messages = document.getElementById('messagesList');
            if (messages) messages.replaceChildren();
        }

        document.querySelectorAll('.chat-item').forEach(function (item) {
            item.classList.remove('active');
        });
        const selected = sourceElement instanceof Element
            ? sourceElement
            : (window.event && window.event.currentTarget instanceof Element ? window.event.currentTarget : null);
        if (selected) {
            selected.classList.add('active');
        }

        const welcome = document.getElementById('welcomeScreen');
        const content = document.getElementById('chatContent');
        if (welcome) welcome.classList.add('d-none');
        if (content) content.classList.remove('d-none');

        const title = document.getElementById('chatTitle');
        const hasTitle = chatInfo.title !== null && chatInfo.title !== undefined && asString(chatInfo.title) !== '';
        if (title) {
            title.textContent = hasTitle ? asString(chatInfo.title) : localized('common.unknown', {}, 'Unknown');
            if (hasTitle) title.removeAttribute('data-i18n-fallback');
            else title.dataset.i18nFallback = 'common.unknown';
        }

        if (chatInfo.other_user) {
            const otherUser = chatInfo.other_user;
            const online = otherUser.is_online == 1 || otherUser.is_online === true;
            const status = document.getElementById('chatStatus');
            if (status) {
                const lastSeen = formatTime(otherUser.last_seen);
                status.textContent = online
                    ? localized('chat.online', {}, 'Online')
                    : localized('chat.last_seen', {time: lastSeen}, 'Last seen ' + lastSeen);
                status.className = online ? 'chat-status online' : 'chat-status';
            }
            const indicator = document.getElementById('onlineIndicator');
            if (indicator) indicator.classList.toggle('d-none', !online);
        }

        const avatar = document.getElementById('chatAvatar');
        if (avatar) {
            avatar.replaceChildren();
            appendAvatar(avatar, chatInfo.chat_avatar, title ? title.textContent : '', {
                alt: localized(
                    'files.avatar_named',
                    {name: title ? title.textContent : localized('common.unknown', {}, 'Unknown')},
                    (title ? title.textContent : localized('common.unknown', {}, 'Unknown')) + ' avatar'
                )
            });
        }

        loadMessages(safeChatId);
        if (window.innerWidth <= 768) {
            hideMobileSidebar();
            hideBottomNav();
        }
    };

    function createMessageAvatar(message) {
        const holder = document.createElement('div');
        appendAvatar(holder, message.avatar, message.first_name, {
            messageAvatar: true,
            alt: localized('profile.sender_avatar', {}, 'Sender avatar')
        });
        const avatar = holder.firstChild;
        if (avatar instanceof Element && avatar.tagName === 'IMG') {
            avatar.dataset.i18nAlt = 'profile.sender_avatar';
        }
        return avatar;
    }

    function appendMessageStatus(parent, message) {
        const read = Number(message.read_count) > 0;
        const status = document.createElement('div');
        status.className = 'message-status ' + (read ? 'status-read' : 'status-delivered');
        appendIcon(status, read ? 'fas fa-check-double' : 'fas fa-check');
        parent.appendChild(status);
    }

    function appendReply(parent, message) {
        const replyId = positiveInteger(message.reply_to_message_id);
        const deleted = message.reply_is_deleted === true || Number(message.reply_is_deleted) === 1;
        if (!replyId || (!deleted && !message.reply_content)) {
            return;
        }
        const reply = document.createElement('div');
        reply.className = 'reply-to';
        reply.addEventListener('click', function () {
            jumpToMessage(replyId);
        });
        const hasSender = message.reply_sender_name !== null && message.reply_sender_name !== undefined &&
            asString(message.reply_sender_name) !== '';
        const sender = appendTextElement(
            reply,
            'div',
            'reply-sender reply-sender-user',
            hasSender ? asString(message.reply_sender_name) : localized('common.user', {}, 'User')
        );
        sender.dir = 'auto';
        if (hasSender) sender.dataset.i18nIgnore = '';
        else sender.dataset.i18nFallback = 'common.user';
        const replyText = asString(message.reply_content);
        const replyContent = appendTextElement(
            reply,
            'div',
            'reply-content',
            deleted
                ? localized('chat.deleted', {}, 'This message was deleted')
                : replyText.slice(0, 100) + (replyText.length > 100 ? '...' : '')
        );
        if (deleted) {
            replyContent.dataset.i18nReplyDeleted = 'true';
        } else {
            replyContent.dir = 'auto';
            replyContent.dataset.i18nIgnore = '';
        }
        parent.appendChild(reply);
    }

    function appendAttachment(parent, message) {
        const hasFileName = message.file_name !== null && message.file_name !== undefined &&
            asString(message.file_name) !== '';
        const fileName = hasFileName
            ? asString(message.file_name)
            : localized('files.attachment_name', {}, 'attachment');
        const attachmentUrl = safeAttachmentUrl(message.file_path);
        const markFileNameFallback = function (element) {
            if (!hasFileName && element) element.dataset.i18nFallback = 'files.attachment_name';
            return element;
        };

        if (message.message_type === 'image') {
            const wrapper = document.createElement('div');
            wrapper.className = 'image-message';
            if (attachmentUrl) {
                const image = document.createElement('img');
                image.src = attachmentUrl;
                image.alt = fileName;
                if (!hasFileName) image.dataset.i18nFileNameFallback = 'true';
                image.decoding = 'async';
                image.draggable = false;
                image.addEventListener('click', function () {
                    window.showImagePreview(attachmentUrl);
                });
                wrapper.appendChild(image);
            } else {
                appendTextElement(wrapper, 'span', 'text-muted', 'Attachment unavailable');
            }
            parent.appendChild(wrapper);
        } else if (message.message_type === 'audio') {
            const wrapper = document.createElement('div');
            wrapper.className = 'audio-message';
            if (attachmentUrl) {
                const audio = document.createElement('audio');
                audio.controls = true;
                audio.preload = 'metadata';
                audio.src = attachmentUrl;
                audio.dataset.i18nAttachment = 'audio';
                audio.dataset.i18nFileName = fileName;
                if (!hasFileName) audio.dataset.i18nFileNameFallback = 'true';
                audio.setAttribute('aria-label', localized(
                    'files.audio_attachment',
                    {name: fileName},
                    'Audio attachment: ' + fileName
                ));
                wrapper.appendChild(audio);
            } else {
                appendTextElement(wrapper, 'span', 'text-muted', 'Audio unavailable');
            }
            const details = document.createElement('div');
            details.className = 'audio-message-meta';
            markFileNameFallback(appendTextElement(details, 'span', 'file-name', fileName));
            appendFileSize(details, 'span', 'file-size', message.file_size);
            wrapper.appendChild(details);
            parent.appendChild(wrapper);
        } else if (message.message_type === 'video') {
            const wrapper = document.createElement('div');
            wrapper.className = 'video-message';
            if (attachmentUrl) {
                const video = document.createElement('video');
                video.controls = true;
                video.preload = 'metadata';
                video.src = attachmentUrl;
                video.dataset.i18nAttachment = 'video';
                video.dataset.i18nFileName = fileName;
                if (!hasFileName) video.dataset.i18nFileNameFallback = 'true';
                video.setAttribute('aria-label', localized(
                    'files.video_attachment',
                    {name: fileName},
                    'Video attachment: ' + fileName
                ));
                wrapper.appendChild(video);
            } else {
                appendTextElement(wrapper, 'span', 'text-muted', 'Video unavailable');
            }
            const details = document.createElement('div');
            details.className = 'video-message-meta';
            markFileNameFallback(appendTextElement(details, 'span', 'file-name', fileName));
            appendFileSize(details, 'span', 'file-size', message.file_size);
            wrapper.appendChild(details);
            parent.appendChild(wrapper);
        } else {
            const wrapper = document.createElement('div');
            wrapper.className = 'file-message';
            const iconInfo = getFileIcon(fileName);
            const icon = document.createElement('div');
            icon.className = 'file-icon';
            appendIcon(icon, 'fas ' + asString(iconInfo.icon));
            wrapper.appendChild(icon);

            const info = document.createElement('div');
            info.className = 'file-info';
            markFileNameFallback(appendTextElement(info, 'div', 'file-name', fileName));
            appendFileSize(info, 'div', 'file-size', message.file_size);
            wrapper.appendChild(info);

            if (attachmentUrl) {
                const download = document.createElement('a');
                download.href = attachmentUrl;
                download.className = 'btn btn-sm btn-link text-white';
                download.dataset.i18nAttachment = 'download';
                download.dataset.i18nFileName = fileName;
                if (!hasFileName) download.dataset.i18nFileNameFallback = 'true';
                download.setAttribute('aria-label', localized('files.download', {name: fileName}, 'Download ' + fileName));
                appendIcon(download, 'fas fa-download');
                wrapper.appendChild(download);
            }
            parent.appendChild(wrapper);
        }

        if (message.content && message.content !== message.file_name) {
            const caption = appendTextElement(parent, 'div', 'message-caption', message.content);
            caption.dir = 'auto';
            caption.dataset.i18nIgnore = '';
        }
    }

    window.renderMessages = function secureRenderMessages(messages, isPrepend, isNewMessage) {
        const container = document.getElementById('messagesList');
        const scrollContainer = document.getElementById('messagesContainer');
        if (!container || !scrollContainer || !currentUser) {
            return;
        }

        const prepend = Boolean(isPrepend);
        const newMessage = Boolean(isNewMessage);
        const scrollEpoch = ++messageScrollRequestEpoch;
        const oldScrollHeight = prepend ? scrollContainer.scrollHeight : 0;
        const oldScrollTop = prepend ? scrollContainer.scrollTop : 0;
        const wasAtBottom = scrollContainer.scrollTop + scrollContainer.clientHeight >= scrollContainer.scrollHeight - 50;
        let safeMessages = Array.isArray(messages) ? messages : [];

        if (newMessage) {
            const existingIds = new Set(Array.from(container.querySelectorAll('[data-message-id]')).map(function (node) {
                return node.dataset.messageId;
            }));
            safeMessages = safeMessages.filter(function (message) {
                const id = positiveInteger(message && message.id);
                return id && !existingIds.has(String(id));
            });
            if (safeMessages.length === 0) return;
        }
        const includesOwnNewMessage = newMessage && safeMessages.some(function (message) {
            return positiveInteger(message && message.sender_id) === positiveInteger(currentUser && currentUser.id);
        });

        const previousLiveMode = container.getAttribute('aria-live') || 'polite';
        if (prepend || (!prepend && !newMessage)) {
            container.setAttribute('aria-live', 'off');
        }

        if (!prepend && !newMessage) {
            container.replaceChildren();
        }

        const fragment = document.createDocumentFragment();
        safeMessages.forEach(function (message, index) {
            const messageId = positiveInteger(message && message.id);
            const senderId = positiveInteger(message && message.sender_id);
            if (!messageId || !senderId || container.querySelector('[data-message-id="' + messageId + '"]')) {
                return;
            }

            const ownMessage = senderId === Number(currentUser.id);
            const messageRow = document.createElement('div');
            messageRow.className = 'message ' + (ownMessage ? 'outgoing' : 'incoming');
            messageRow.dataset.messageId = String(messageId);
            messageRow.dataset.senderId = String(senderId);
            messageRow.dataset.createdAt = asString(message.created_at);
            messageRow.dataset.messageType = asString(message.message_type || 'text');
            messageRow.dataset.isUnread = message.is_unread_for_user === true || Number(message.is_unread_for_user) === 1
                ? 'true'
                : 'false';
            if (newMessage && index === safeMessages.length - 1) {
                messageRow.classList.add('new-message');
            }

            const createSender = function (interactive) {
                const sender = document.createElement('div');
                sender.className = 'sender-avatar';
                if (interactive) {
                    sender.tabIndex = 0;
                    sender.setAttribute('role', 'button');
                    sender.setAttribute('data-i18n-aria-label', 'profile.open_sender');
                    sender.setAttribute('aria-label', localized('profile.open_sender', {}, 'Open sender profile'));
                    const openProfile = function () { window.showUserProfile(senderId); };
                    sender.addEventListener('click', openProfile);
                    sender.addEventListener('keydown', function (event) {
                        if (event.key === 'Enter' || event.key === ' ') {
                            event.preventDefault();
                            openProfile();
                        }
                    });
                }
                sender.appendChild(createMessageAvatar(message));
                return sender;
            };

            if (!ownMessage) messageRow.appendChild(createSender(true));

            const content = document.createElement('div');
            content.className = 'message-content';
            appendReply(content, message);
            if (message.message_type === 'text') {
                const text = appendTextElement(content, 'div', 'message-text', asString(message.content));
                text.dir = 'auto';
                text.dataset.i18nIgnore = '';
            } else {
                appendAttachment(content, message);
            }
            appendTextElement(content, 'div', 'message-time', formatTime(message.created_at));
            if (ownMessage) appendMessageStatus(content, message);
            content.addEventListener('contextmenu', function (event) {
                showMessageContextMenu(event, messageId);
            });
            messageRow.appendChild(content);

            if (ownMessage) messageRow.appendChild(createSender(false));
            fragment.appendChild(messageRow);
        });

        if (prepend) {
            container.insertBefore(fragment, container.firstChild);
        } else {
            container.appendChild(fragment);
        }

        if (prepend || (!prepend && !newMessage)) {
            window.setTimeout(function () {
                if (container.isConnected) container.setAttribute('aria-live', previousLiveMode === 'off' ? 'polite' : previousLiveMode);
            }, 0);
        }

        if (prepend) {
            scrollContainer.scrollTop = oldScrollTop + scrollContainer.scrollHeight - oldScrollHeight;
        } else if (window.pmSuppressNewMessageAutoScroll !== true &&
            (wasAtBottom || isInitialLoad || includesOwnNewMessage)) {
            const scrollChatId = String(currentChatId || '');
            window.setTimeout(function () {
                if (scrollEpoch !== messageScrollRequestEpoch ||
                    String(currentChatId || '') !== scrollChatId ||
                    window.pmSuppressNewMessageAutoScroll === true ||
                    !scrollContainer.isConnected) return;
                scrollContainer.scrollTop = scrollContainer.scrollHeight;
            }, 50);
        }
    };

    function replyPreviewSenderName(senderKind, senderName) {
        if (senderKind === 'self') return localized('common.you', {}, 'You');
        if (senderKind === 'fallback') return localized('common.user', {}, 'User');
        return asString(senderName);
    }

    window.showReplyPreview = function secureShowReplyPreview(messageId, senderName, messageContent, senderKind) {
        const existing = document.querySelector('.reply-preview');
        if (existing) existing.remove();
        const safeMessageId = positiveInteger(messageId);
        const inputContainer = document.querySelector('.message-input-container');
        if (!safeMessageId || !inputContainer) return;
        const kind = ['self', 'fallback', 'name'].includes(senderKind)
            ? senderKind
            : (asString(senderName) ? 'name' : 'fallback');
        const rawName = kind === 'name' ? asString(senderName) : '';
        const displayName = replyPreviewSenderName(kind, rawName);

        const preview = document.createElement('div');
        preview.className = 'reply-preview';
        const close = document.createElement('button');
        close.type = 'button';
        close.className = 'reply-close';
        close.setAttribute('data-i18n-aria-label', 'chat.reply_cancel');
        close.setAttribute('aria-label', localized('chat.reply_cancel', {}, 'Cancel reply'));
        close.textContent = '×';
        close.addEventListener('click', function () { window.clearReply(); });
        preview.appendChild(close);
        const replySender = appendTextElement(preview, 'div', 'reply-sender', localized(
            'chat.replying_to',
            {name: displayName},
            'Replying to ' + displayName
        ));
        replySender.dataset.i18nReplySenderKind = kind;
        if (kind === 'name') replySender.dataset.i18nReplySenderName = rawName;
        const replyText = asString(messageContent);
        const replyContent = appendTextElement(
            preview,
            'div',
            'reply-content',
            replyText.slice(0, 100) + (replyText.length > 100 ? '...' : '')
        );
        replyContent.dir = 'auto';
        replyContent.dataset.i18nIgnore = '';
        preview.dataset.replyTo = String(safeMessageId);
        inputContainer.insertBefore(preview, inputContainer.firstChild);
    };

    window.renderUserSearchResults = function secureRenderUserSearchResults(users) {
        const container = document.getElementById('userSearchResults');
        if (!container) return;
        container.replaceChildren();

        (Array.isArray(users) ? users : []).forEach(function (user) {
            const userId = positiveInteger(user && user.id);
            if (!userId) return;
            const item = document.createElement('div');
            item.className = 'chat-item';
            item.addEventListener('click', function () { window.startChatWithUser(userId); });

            const avatarContainer = document.createElement('div');
            avatarContainer.className = 'avatar-container';
            const avatar = document.createElement('div');
            avatar.className = 'chat-avatar';
            appendAvatar(avatar, user.avatar, user.first_name, {alt: 'User avatar'});
            avatarContainer.appendChild(avatar);
            if (user.is_online == 1 || user.is_online === true) {
                const indicator = document.createElement('div');
                indicator.className = 'online-indicator';
                avatarContainer.appendChild(indicator);
            }
            item.appendChild(avatarContainer);

            const info = document.createElement('div');
            info.className = 'chat-info';
            appendTextElement(info, 'div', 'chat-name', (asString(user.first_name) + ' ' + asString(user.last_name)).trim());
            appendTextElement(info, 'div', 'chat-last-message', '@' + asString(user.username));
            item.appendChild(info);
            container.appendChild(item);
        });
    };

    function appendProfileAvatar(parent, user) {
        const avatar = document.createElement('div');
        avatar.className = 'user-profile-avatar';
        appendAvatar(avatar, user.avatar, user.first_name, {alt: 'User avatar'});
        parent.appendChild(avatar);
    }

    function appendProfileIdentity(parent, user) {
        appendTextElement(parent, 'div', 'user-profile-name', (asString(user.first_name) + ' ' + asString(user.last_name)).trim());
        appendTextElement(parent, 'div', 'user-profile-username', '@' + asString(user.username));
        const status = user.is_online == 1 || user.is_online === true
            ? localized('chat.online', {}, 'Online')
            : localized('chat.last_seen', {time: formatTime(user.last_seen)}, 'Last seen ' + formatTime(user.last_seen));
        const statusElement = appendTextElement(parent, 'div', 'user-profile-status', status);
        statusElement.dataset.i18nOnline = user.is_online == 1 || user.is_online === true ? 'true' : 'false';
        statusElement.dataset.i18nLastSeen = asString(user.last_seen);
        if (user.is_online == 1 || user.is_online === true) statusElement.classList.add('text-success');
    }

    window.refreshLocalizedSecurityChrome = function refreshLocalizedSecurityChrome() {
        document.querySelectorAll('#chatList .chat-item').forEach(function (row) {
            const refs = row.__pmChatRefs;
            const chat = row.__pmChatData;
            const rawTitle = asString(chat && chat.title);
            const title = rawTitle || localized('common.unknown', {}, 'Unknown');
            const image = refs && refs.avatar && refs.avatar.querySelector('img');
            if (image) {
                image.alt = localized('files.avatar_named', {name: title}, title + ' avatar');
            }
            const unread = Number(chat && chat.unread_count);
            if (refs && refs.unread && Number.isSafeInteger(unread) && unread > 0) {
                refs.unread.textContent = localizedNumber(Math.min(unread, 9999));
            }
            if (refs && refs.name && (!chat || !asString(chat.title))) {
                refs.name.textContent = localized('common.unknown', {}, 'Unknown');
            }
        });
        const chatTitle = document.getElementById('chatTitle');
        if (chatTitle && chatTitle.dataset.i18nFallback === 'common.unknown') {
            chatTitle.textContent = localized('common.unknown', {}, 'Unknown');
        }
        const activeChatAvatar = document.querySelector('#chatAvatar img');
        const activeChatTitle = asString(currentChatInfo && currentChatInfo.title) ||
            localized('common.unknown', {}, 'Unknown');
        if (activeChatAvatar) {
            activeChatAvatar.alt = localized(
                'files.avatar_named', {name: activeChatTitle}, activeChatTitle + ' avatar'
            );
        }
        document.querySelectorAll('[data-i18n-reply-sender-kind]').forEach(function (element) {
            const kind = asString(element.dataset.i18nReplySenderKind);
            const rawName = kind === 'name' ? asString(element.dataset.i18nReplySenderName) : '';
            const displayName = replyPreviewSenderName(kind, rawName);
            element.textContent = localized(
                'chat.replying_to',
                {name: displayName},
                'Replying to ' + displayName
            );
        });
        document.querySelectorAll('[data-i18n-fallback]').forEach(function (element) {
            element.textContent = localized(element.dataset.i18nFallback, {}, element.textContent);
        });
        document.querySelectorAll('[data-i18n-attachment][data-i18n-file-name]').forEach(function (element) {
            const fileName = element.dataset.i18nFileNameFallback === 'true'
                ? localized('files.attachment_name', {}, 'attachment')
                : asString(element.dataset.i18nFileName);
            if (element.dataset.i18nFileNameFallback === 'true') element.dataset.i18nFileName = fileName;
            const type = element.dataset.i18nAttachment;
            if (type === 'audio') {
                element.setAttribute('aria-label', localized(
                    'files.audio_attachment', {name: fileName}, 'Audio attachment: ' + fileName
                ));
            } else if (type === 'video') {
                element.setAttribute('aria-label', localized(
                    'files.video_attachment', {name: fileName}, 'Video attachment: ' + fileName
                ));
            } else if (type === 'download') {
                element.setAttribute('aria-label', localized(
                    'files.download', {name: fileName}, 'Download ' + fileName
                ));
            }
        });
        document.querySelectorAll('.image-message img[data-i18n-file-name-fallback="true"]').forEach(function (image) {
            image.alt = localized('files.attachment_name', {}, 'attachment');
        });
        document.querySelectorAll('.user-profile-status[data-i18n-online]').forEach(function (element) {
            const online = element.dataset.i18nOnline === 'true';
            const lastSeen = formatTime(element.dataset.i18nLastSeen);
            element.textContent = online
                ? localized('chat.online', {}, 'Online')
                : localized('chat.last_seen', {time: lastSeen}, 'Last seen ' + lastSeen);
        });
        document.querySelectorAll('.reply-content[data-i18n-reply-deleted="true"]').forEach(function (element) {
            element.textContent = localized('chat.deleted', {}, 'This message was deleted');
        });
        document.querySelectorAll('.search-result-meta[data-i18n-timestamp]').forEach(function (element) {
            element.textContent = formatTime(element.dataset.i18nTimestamp);
        });
        document.querySelectorAll('[data-i18n-bytes]').forEach(function (element) {
            const bytes = Number(element.dataset.i18nBytes);
            if (Number.isSafeInteger(bytes) && bytes >= 0) element.textContent = formatFileSize(bytes);
        });
        document.querySelectorAll('[data-i18n-profile-label]').forEach(function (element) {
            element.textContent = localized(element.dataset.i18nProfileLabel, {}, element.textContent);
        });
        document.querySelectorAll('img[data-i18n-alt="profile.sender_avatar"]').forEach(function (image) {
            image.alt = localized('profile.sender_avatar', {}, 'Sender avatar');
        });
    };

    function appendProfileField(parent, label, value, className) {
        if (!value) return;
        const row = document.createElement('div');
        row.className = className || 'profile-info-item mb-2';
        const strong = document.createElement('strong');
        const labelKey = {
            'Email:': 'profile.email_label',
            'Phone:': 'profile.phone_label',
            'Bio:': 'profile.bio_label'
        }[label];
        strong.textContent = labelKey ? localized(labelKey, {}, label) : label;
        if (labelKey) strong.dataset.i18nProfileLabel = labelKey;
        row.appendChild(strong);
        const output = document.createElement('bdi');
        output.textContent = asString(value);
        output.dataset.i18nIgnore = '';
        row.append(' ', output);
        parent.appendChild(row);
    }

    window.showChatInfo = function secureShowChatInfo() {
        if (!currentChatInfo || currentChatInfo.type !== 'private' || !currentChatInfo.other_user) return;
        const useSidePanel = typeof window.openChatSidePanel === 'function' &&
            window.openChatSidePanel('info') === true;
        const content = document.getElementById(useSidePanel ? 'chatSideInfoContent' : 'chatInfoContent');
        if (!content) return;
        const inactiveContent = document.getElementById(useSidePanel ? 'chatInfoContent' : 'chatSideInfoContent');
        if (inactiveContent) inactiveContent.replaceChildren();
        content.replaceChildren();

        const user = currentChatInfo.other_user;
        const header = document.createElement('div');
        header.className = 'user-profile-header';
        appendProfileAvatar(header, user);
        appendProfileIdentity(header, user);

        const additional = document.createElement('div');
        additional.className = 'profile-additional-info mt-3';
        if (user.show_email && user.email) appendProfileField(additional, 'Email:', user.email);
        if (user.show_phone && user.phone) appendProfileField(additional, 'Phone:', user.phone);
        if (additional.childNodes.length) header.appendChild(additional);
        if (user.show_bio && user.bio) {
            const bio = document.createElement('div');
            bio.className = 'user-profile-bio mt-3';
            appendTextElement(bio, 'h6', 'text-muted mb-2', 'About');
            appendTextElement(bio, 'div', 'bio-content', user.bio);
            header.appendChild(bio);
        }
        content.appendChild(header);

        const details = document.createElement('div');
        details.className = 'chat-info-section';
        appendTextElement(details, 'h6', '', 'Chat Details');
        const row = document.createElement('div');
        row.className = 'row';
        const type = document.createElement('div');
        type.className = 'col-6';
        appendTextElement(type, 'small', 'text-muted', 'Chat Type');
        appendTextElement(type, 'div', '', 'Private Chat');
        row.appendChild(type);
        const count = document.createElement('div');
        count.className = 'col-6';
        appendTextElement(count, 'small', 'text-muted', 'Messages');
        const countValue = appendTextElement(count, 'div', '', 'Loading...');
        countValue.id = 'messageCount';
        row.appendChild(count);
        details.appendChild(row);
        content.appendChild(details);

        loadChatStats(countValue);
        if (!useSidePanel) {
            new bootstrap.Modal(document.getElementById('chatInfoModal')).show();
        }
    };

    function appendHighlightedText(parent, value, query) {
        const text = asString(value);
        const needle = asString(query);
        if (!needle) {
            parent.textContent = text;
            return;
        }
        const pattern = new RegExp(escapeRegExp(needle), 'gi');
        let cursor = 0;
        let match;
        while ((match = pattern.exec(text)) !== null) {
            parent.appendChild(document.createTextNode(text.slice(cursor, match.index)));
            const highlight = document.createElement('span');
            highlight.className = 'search-highlight';
            highlight.textContent = match[0];
            parent.appendChild(highlight);
            cursor = match.index + match[0].length;
            if (match[0].length === 0) pattern.lastIndex += 1;
        }
        parent.appendChild(document.createTextNode(text.slice(cursor)));
    }

    window.renderSearchResults = function secureRenderSearchResults(messages, query, targetId) {
        const container = document.getElementById(targetId || 'chatSearchResults');
        if (!container) return;
        container.replaceChildren();
        const results = Array.isArray(messages) ? messages : [];
        if (!results.length) {
            appendTextElement(container, 'div', 'text-muted text-center py-3', 'No messages found');
            return;
        }

        results.forEach(function (message) {
            const messageId = positiveInteger(message && message.id);
            if (!messageId) return;
            const result = document.createElement('button');
            result.type = 'button';
            result.className = 'search-result-item';
            const openResult = function () {
                if (typeof window.openMessageSearchResult === 'function') {
                    window.openMessageSearchResult(messageId);
                } else {
                    jumpToMessage(messageId);
                }
            };
            result.addEventListener('click', openResult);
            const sender = document.createElement('div');
            sender.className = 'search-result-user';
            sender.dir = 'auto';
            sender.dataset.i18nIgnore = '';
            const strong = document.createElement('strong');
            strong.textContent = (asString(message.first_name) + ' ' + asString(message.last_name)).trim() + ':';
            sender.appendChild(strong);
            result.appendChild(sender);
            const body = document.createElement('div');
            body.className = 'search-result-message';
            body.dir = 'auto';
            body.dataset.i18nIgnore = '';
            appendHighlightedText(body, message.content, query);
            result.appendChild(body);
            const meta = appendTextElement(result, 'div', 'search-result-meta', formatTime(message.created_at));
            meta.dataset.i18nTimestamp = asString(message.created_at);
            container.appendChild(result);
        });
    };

    window.renderUserProfile = function secureRenderUserProfile(user) {
        const userId = positiveInteger(user && user.id);
        const content = document.getElementById('userProfileContent');
        if (!userId || !content) return;
        content.replaceChildren();
        const header = document.createElement('div');
        header.className = 'user-profile-header';
        appendProfileAvatar(header, user);
        appendProfileIdentity(header, user);
        if (user.bio) appendProfileField(header, 'Bio:', user.bio, 'user-profile-bio');
        if (user.phone) appendProfileField(header, 'Phone:', user.phone, 'mt-3');
        content.appendChild(header);

        const sendButton = document.getElementById('sendMessageBtn');
        if (sendButton) sendButton.classList.toggle('d-none', userId === Number(currentUser && currentUser.id));
        new bootstrap.Modal(document.getElementById('userProfileModal')).show();
    };

    let attachmentPreviewObjectUrl = null;
    window.releaseAttachmentPreviewObjectUrl = function releaseAttachmentPreviewObjectUrl() {
        if (attachmentPreviewObjectUrl) {
            URL.revokeObjectURL(attachmentPreviewObjectUrl);
            attachmentPreviewObjectUrl = null;
        }
    };

    window.showAttachmentPreview = function secureShowAttachmentPreview(file) {
        const preview = document.getElementById('attachmentPreview');
        const content = document.getElementById('previewContent');
        if (!(file instanceof File) || !preview || !content) return;
        window.releaseAttachmentPreviewObjectUrl();
        content.replaceChildren();

        const row = document.createElement('div');
        row.className = 'd-flex align-items-center mb-3';
        const normalizedType = asString(file.type).toLowerCase().split(';', 1)[0].trim();
        if (['image/jpeg', 'image/png', 'image/gif', 'image/webp'].includes(normalizedType)) {
            const image = document.createElement('img');
            image.alt = 'Preview';
            image.className = 'attachment-preview-image';
            const objectUrl = URL.createObjectURL(file);
            attachmentPreviewObjectUrl = objectUrl;
            image.src = objectUrl;
            const releaseImageUrl = function () {
                URL.revokeObjectURL(objectUrl);
                if (attachmentPreviewObjectUrl === objectUrl) attachmentPreviewObjectUrl = null;
            };
            image.addEventListener('load', releaseImageUrl, {once: true});
            image.addEventListener('error', releaseImageUrl, {once: true});
            row.appendChild(image);
        } else if (normalizedType.startsWith('audio/')) {
            const audio = document.createElement('audio');
            attachmentPreviewObjectUrl = URL.createObjectURL(file);
            audio.src = attachmentPreviewObjectUrl;
            audio.controls = true;
            audio.preload = 'metadata';
            audio.className = 'attachment-audio-preview';
            audio.setAttribute('aria-label', 'Preview recording');
            row.appendChild(audio);
        } else {
            const iconInfo = getFileIcon(file.name);
            const icon = document.createElement('div');
            icon.className = 'file-icon me-3 attachment-preview-file-icon';
            appendIcon(icon, 'fas ' + asString(iconInfo.icon));
            row.appendChild(icon);
        }

        const info = document.createElement('div');
        info.className = 'flex-grow-1';
        const fileName = appendTextElement(info, 'bdi', 'fw-bold file-name', file.name);
        fileName.dir = 'auto';
        fileName.dataset.i18nIgnore = '';
        appendFileSize(info, 'div', 'text-muted small', file.size);
        const ready = appendTextElement(info, 'div', 'text-success small mt-1', 'Ready to send');
        ready.prepend(appendIcon(document.createDocumentFragment(), 'fas fa-check-circle me-1'));
        row.appendChild(info);
        content.appendChild(row);
        preview.classList.remove('d-none');
        const input = document.getElementById('messageInput');
        if (input) {
            input.placeholder = 'Add a caption...';
            input.focus();
        }
    };

    window.showImagePreview = function secureShowImagePreview(source) {
        const safeSource = safeAttachmentUrl(source);
        const image = document.getElementById('previewImage');
        const modal = document.getElementById('imagePreviewModal');
        if (!safeSource || !image || !modal) return;
        image.src = safeSource;
        new bootstrap.Modal(modal).show();
    };

    window.loadUserProfile = function secureLoadUserProfile() {
        if (!currentUser) return;
        const values = {
            profileFirstName: currentUser.first_name,
            profileLastName: currentUser.last_name,
            profileUsername: currentUser.username,
            profileBio: currentUser.bio,
            profilePhone: currentUser.phone
        };
        Object.keys(values).forEach(function (id) {
            const field = document.getElementById(id);
            if (field) field.value = asString(values[id]);
        });
        const name = document.getElementById('profileNameLarge');
        const username = document.getElementById('profileUsernameLarge');
        if (name) name.textContent = (asString(currentUser.first_name) + ' ' + asString(currentUser.last_name)).trim();
        if (username) username.textContent = '@' + asString(currentUser.username || 'username');
        const avatar = document.getElementById('profileAvatarLarge');
        if (avatar) {
            avatar.replaceChildren();
            appendAvatar(avatar, currentUser.avatar, currentUser.first_name, {alt: 'Your avatar'});
            const overlay = document.createElement('div');
            overlay.className = 'avatar-upload-overlay';
            appendIcon(overlay, 'fas fa-camera');
            avatar.appendChild(overlay);
        }
    };

    const legacyShow2FASetupModal = window.show2FASetupModal;
    if (typeof legacyShow2FASetupModal === 'function') {
        window.show2FASetupModal = function secureShow2FASetupModal(data) {
            const secret = /^[A-Z2-7]{16,64}$/i.test(asString(data && data.secret)) ? asString(data.secret).toUpperCase() : '';
            const qrCode = asString(data && data.qr_code);
            const safeQr = /^data:image\/png;base64,[a-z0-9+/=]+$/i.test(qrCode) ? qrCode : '';
            if (!secret) {
                window.showToast('Two-factor setup data was invalid. Please try again.', 'error');
                return;
            }
            return legacyShow2FASetupModal.call(this, Object.assign({}, data, {
                secret: secret,
                manual_entry_key: asString(data.manual_entry_key),
                account: asString(data.account),
                issuer: asString(data.issuer),
                qr_code: safeQr,
                qr_available: Boolean(data.qr_available && safeQr)
            }));
        };
    }

    const legacyShowBackupCodes = window.showBackupCodes;
    if (typeof legacyShowBackupCodes === 'function') {
        window.showBackupCodes = function secureShowBackupCodes(codes) {
            const safeCodes = (Array.isArray(codes) ? codes : []).filter(function (code) {
                return /^[A-F0-9]{8}$/.test(asString(code));
            });
            if (!safeCodes.length) {
                window.showToast('Backup codes could not be displayed safely.', 'error');
                return;
            }
            return legacyShowBackupCodes.call(this, safeCodes);
        };
    }

    const legacyUpdateStorageDisplay = window.updateStorageDisplay;
    if (typeof legacyUpdateStorageDisplay === 'function') {
        window.updateStorageDisplay = function secureUpdateStorageDisplay(storage) {
            const safeStorage = {};
            ['messages', 'media', 'documents', 'total'].forEach(function (key) {
                const value = asString(storage && storage[key]);
                safeStorage[key] = /^\d+(?:\.\d{1,2})? MB$/.test(value) ? value : '0 MB';
            });
            ['messages_bytes', 'media_bytes', 'documents_bytes', 'total_bytes'].forEach(function (key) {
                const value = Number(storage && storage[key]);
                if (Number.isSafeInteger(value) && value >= 0) safeStorage[key] = value;
            });
            return legacyUpdateStorageDisplay.call(this, safeStorage);
        };
    }

    let credentialModalSequence = 0;

    function requestCurrentPassword(options) {
        const prompt = options || {};
        const requirePassword = prompt.requirePassword !== false;
        const requireSecondFactor = Boolean(prompt.requireSecondFactor);
        return new Promise(function (resolve) {
            const modal = document.createElement('div');
            modal.className = 'modal fade';
            modal.tabIndex = -1;
            modal.setAttribute('role', 'dialog');
            modal.setAttribute('aria-modal', 'true');
            modal.setAttribute('aria-hidden', 'true');
            const dialog = document.createElement('div');
            dialog.className = 'modal-dialog modal-dialog-centered';
            const panel = document.createElement('div');
            panel.className = 'modal-content';
            const form = document.createElement('form');
            const header = document.createElement('div');
            header.className = 'modal-header';
            const title = appendTextElement(
                header,
                'h5',
                'modal-title',
                prompt.title || 'Confirm your password'
            );
            title.id = 'credential-confirmation-title-' + (++credentialModalSequence);
            modal.setAttribute('aria-labelledby', title.id);
            const close = document.createElement('button');
            close.type = 'button';
            close.className = 'btn-close btn-close-white';
            close.setAttribute('data-bs-dismiss', 'modal');
            close.setAttribute('aria-label', 'Close');
            header.appendChild(close);
            form.appendChild(header);
            const body = document.createElement('div');
            body.className = 'modal-body';
            appendTextElement(
                body,
                'p',
                'text-muted',
                prompt.description || 'Re-enter your password before replacing your recovery codes.'
            );
            let passwordInput = null;
            if (requirePassword) {
                const passwordLabel = document.createElement('label');
                passwordLabel.className = 'form-label';
                passwordLabel.textContent = 'Current password';
                passwordInput = document.createElement('input');
                passwordInput.type = 'password';
                passwordInput.className = 'form-control';
                passwordInput.autocomplete = 'current-password';
                passwordInput.required = true;
                passwordInput.maxLength = 1024;
                passwordInput.setAttribute('aria-label', 'Current password');
                passwordLabel.appendChild(passwordInput);
                body.appendChild(passwordLabel);
            }
            let secondFactorInput = null;
            if (requireSecondFactor) {
                const secondFactorLabel = document.createElement('label');
                secondFactorLabel.className = requirePassword ? 'form-label mt-3' : 'form-label';
                secondFactorLabel.textContent = 'Authenticator or backup code';
                secondFactorInput = document.createElement('input');
                secondFactorInput.type = 'text';
                secondFactorInput.className = 'form-control';
                secondFactorInput.autocomplete = 'one-time-code';
                secondFactorInput.inputMode = 'text';
                secondFactorInput.required = true;
                secondFactorInput.minLength = 6;
                secondFactorInput.maxLength = 8;
                secondFactorInput.spellcheck = false;
                secondFactorInput.setAttribute('aria-label', 'Authenticator or backup code');
                secondFactorInput.addEventListener('input', function () {
                    secondFactorInput.setCustomValidity('');
                });
                secondFactorLabel.appendChild(secondFactorInput);
                body.appendChild(secondFactorLabel);
            }
            form.appendChild(body);
            const footer = document.createElement('div');
            footer.className = 'modal-footer';
            const cancel = document.createElement('button');
            cancel.type = 'button';
            cancel.className = 'btn btn-secondary';
            cancel.setAttribute('data-bs-dismiss', 'modal');
            cancel.textContent = 'Cancel';
            footer.appendChild(cancel);
            const confirm = document.createElement('button');
            confirm.type = 'submit';
            confirm.className = 'btn btn-primary';
            confirm.textContent = prompt.confirmLabel || 'Generate new codes';
            footer.appendChild(confirm);
            form.appendChild(footer);
            panel.appendChild(form);
            dialog.appendChild(panel);
            modal.appendChild(dialog);
            document.body.appendChild(modal);

            const instance = new bootstrap.Modal(modal);
            let settled = false;
            let modalReady = false;
            let submitted = false;
            let submittedValue = null;
            const finish = function (value) {
                if (settled) return;
                settled = true;
                if (passwordInput) passwordInput.value = '';
                if (secondFactorInput) secondFactorInput.value = '';
                resolve(value);
            };
            form.addEventListener('submit', function (event) {
                event.preventDefault();
                const password = passwordInput ? passwordInput.value : '';
                const secondFactorCode = secondFactorInput ? secondFactorInput.value.trim().toUpperCase() : '';
                if (requirePassword && !password) return;
                if (requireSecondFactor && !/^(?:\d{6}|[A-F0-9]{8})$/.test(secondFactorCode)) {
                    secondFactorInput.setCustomValidity(localized(
                        'security.code_requirement',
                        {},
                        'Enter a 6-digit authenticator code or 8-character backup code.'
                    ));
                    secondFactorInput.reportValidity();
                    return;
                }
                if (secondFactorInput) secondFactorInput.setCustomValidity('');
                submittedValue = requireSecondFactor ? {
                    current_password: password,
                    second_factor_code: secondFactorCode
                } : password;
                submitted = true;
                if (modalReady) instance.hide();
            });
            modal.addEventListener('hidden.bs.modal', function () {
                finish(submitted ? submittedValue : null);
                modal.remove();
            }, {once: true});
            modal.addEventListener('shown.bs.modal', function () {
                modalReady = true;
                (passwordInput || secondFactorInput).focus();
                if (submitted) instance.hide();
            }, {once: true});
            instance.show();
        });
    }

    window.setup2FA = async function secureSetup2FA() {
        const password = await requestCurrentPassword({
            title: 'Confirm two-factor setup',
            description: 'Re-enter your password before connecting an authenticator app.',
            confirmLabel: 'Continue'
        });
        const toggle = document.getElementById('twoFactorToggle');
        if (!password) {
            if (toggle) toggle.checked = false;
            return;
        }

        showLoading('Setting up 2FA...');
        try {
            const response = await fetch('api/settings.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify({action: 'setup_2fa', current_password: password})
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.message || 'Failed to set up 2FA');
            }
            window.show2FASetupModal(data);
        } catch (error) {
            if (toggle) toggle.checked = false;
            window.showToast(error.message || 'Failed to set up 2FA', 'error');
        } finally {
            hideLoading();
        }
    };

    window.generateBackupCodes = async function secureGenerateBackupCodes() {
        const verification = await requestCurrentPassword({
            title: 'Confirm recovery-code replacement',
            description: 'Enter your password and a fresh authenticator or backup code before replacing recovery codes.',
            confirmLabel: 'Generate new codes',
            requireSecondFactor: true
        });
        if (!verification) return;
        showLoading('Generating backup codes...');
        try {
            const response = await fetch('api/settings.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify(Object.assign({action: 'get_backup_codes'}, verification))
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.message || 'Password verification failed');
            }
            window.showBackupCodes(data.backup_codes);
        } catch (error) {
            window.showToast(error.message || 'Failed to generate backup codes', 'error');
        } finally {
            hideLoading();
        }
    };

    window.disable2FA = async function secureDisable2FA() {
        const toggle = document.getElementById('twoFactorToggle');
        const verification = await requestCurrentPassword({
            title: 'Disable two-factor authentication',
            description: 'Enter your password and a fresh authenticator or backup code to remove this protection.',
            confirmLabel: 'Disable 2FA',
            requireSecondFactor: true
        });
        if (!verification) {
            if (toggle) toggle.checked = true;
            return;
        }

        showLoading('Disabling 2FA...');
        try {
            const response = await fetch('api/settings.php', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                credentials: 'include',
                body: JSON.stringify(Object.assign({action: 'disable_2fa'}, verification))
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.message || 'Unable to disable 2FA');
            }
            if (window.userSettings) window.userSettings.two_factor_enabled = false;
            window.showToast(
                data.message || 'Two-factor authentication disabled.',
                data.reauthenticate ? 'warning' : 'success'
            );
            window.showSettingsSection('account');
            if (data.reauthenticate) {
                window.setTimeout(function () {
                    window.location.reload();
                }, 1200);
            }
        } catch (error) {
            if (toggle) toggle.checked = true;
            window.showToast(error.message || 'Unable to disable 2FA', 'error');
        } finally {
            hideLoading();
        }
    };

    function passwordByteLength(value) {
        return typeof TextEncoder === 'function'
            ? new TextEncoder().encode(asString(value)).length
            : unescape(encodeURIComponent(asString(value))).length;
    }

    const legacyRegister = window.register;
    if (typeof legacyRegister === 'function') {
        window.register = function secureRegister(event) {
            const password = document.getElementById('registerPassword');
            const length = passwordByteLength(password && password.value);
            if (length < 12 || length > 72) {
                if (event) event.preventDefault();
                window.showToast('Password must be between 12 and 72 characters.', 'error');
                if (password) password.focus();
                return;
            }
            return legacyRegister.apply(this, arguments);
        };
    }

    const legacyChangePassword = window.changePassword;
    if (typeof legacyChangePassword === 'function') {
        window.changePassword = async function secureChangePassword() {
            const password = document.getElementById('newPassword');
            const length = passwordByteLength(password && password.value);
            if (length < 12 || length > 72) {
                window.showToast('New password must be between 12 and 72 characters.', 'error');
                if (password) password.focus();
                return;
            }
            if (window.userSettings && window.userSettings.two_factor_enabled) {
                const verification = await requestCurrentPassword({
                    title: 'Confirm password change',
                    description: 'Enter a fresh authenticator or backup code before changing your password.',
                    confirmLabel: 'Change password',
                    requirePassword: false,
                    requireSecondFactor: true
                });
                if (!verification) return;
                return legacyChangePassword.call(this, verification.second_factor_code);
            }
            return legacyChangePassword.apply(this, arguments);
        };
    }

    const legacyShowSettingsSection = window.showSettingsSection;
    if (typeof legacyShowSettingsSection === 'function') {
        window.showSettingsSection = function secureShowSettingsSection() {
            const result = legacyShowSettingsSection.apply(this, arguments);
            ['newPassword', 'confirmPassword'].forEach(function (id) {
                const input = document.getElementById(id);
                if (input) {
                    input.minLength = 12;
                    input.maxLength = 72;
                }
            });
            const newPassword = document.getElementById('newPassword');
            if (newPassword) newPassword.placeholder = 'Enter 12–72 characters';
            return result;
        };
    }

    window.pmSecurityHardeningReady = true;
}());
