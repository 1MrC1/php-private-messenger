<?php

declare(strict_types=1);

require_once __DIR__ . '/../classes/AttachmentName.php';

function attachmentNameAssert(bool $condition, string $message): void
{
    if (!$condition) {
        throw new RuntimeException($message);
    }
    echo "PASS: {$message}\n";
}

attachmentNameAssert(
    AttachmentName::canonicalDisplayName('Readme.cmd', 'txt') === 'Readme.txt',
    'attacker-supplied executable extension is replaced'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName("invoice.pdf\u{202E}gpj.exe", 'pdf') === 'invoice.pdf_gpj.pdf',
    'bidirectional extension spoofing is neutralized'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName("../report\r\nX-Evil: yes.html", 'txt') === 'report_X-Evil_ yes.txt',
    'path and response-header metacharacters are removed'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName('CON.cmd', 'txt') === '_CON.txt',
    'reserved Windows device names are neutralized'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName('CON.foo.exe', 'txt') === '_CON.foo.txt' &&
        AttachmentName::canonicalDisplayName('LPT1 .archive.cmd', 'pdf') === '_LPT1 .archive.pdf' &&
        AttachmentName::canonicalDisplayName("COM\u{00B2}.payload.exe", 'txt') === "_COM\u{00B2}.payload.txt",
    'Windows device names remain neutralized through extra dots, spaces, and superscript ports'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName('budget.txt::$DATA.exe', 'pdf') === 'budget.txt_$DATA.pdf' &&
        AttachmentName::canonicalDisplayName('folder:report.pages', 'txt') === 'folder_report.txt',
    'NTFS alternate streams and legacy macOS path separators are neutralized'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName("safe\u{061C}name\u{200D}.exe", 'txt') === 'safe_name.txt',
    'bidirectional and zero-width Unicode controls are neutralized'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName('--help.exe', 'txt') === '_--help.txt',
    'leading command-option filenames are neutralized for shell use'
);
attachmentNameAssert(
    AttachmentName::canonicalDisplayName("bad\xC3\x28.exe", 'txt') === 'attachment.txt',
    'invalid UTF-8 falls back to a safe filename'
);
$longUtf8Name = AttachmentName::canonicalDisplayName(str_repeat("\u{1F642}", 100) . '.exe', 'txt');
attachmentNameAssert(
    strlen($longUtf8Name) <= 180 &&
        preg_match('//u', $longUtf8Name) === 1 &&
        substr($longUtf8Name, -4) === '.txt',
    'long UTF-8 names are byte-bounded without splitting a code point'
);
[$asciiName, $utf8Name] = AttachmentName::dispositionNames('Résumé.html', 'text/plain');
attachmentNameAssert(
    $asciiName === 'R_sum.txt' && $utf8Name === 'Résumé.txt',
    'disposition emits safe ASCII and UTF-8 names with the detected extension'
);
[$reservedAsciiName, $reservedUtf8Name] = AttachmentName::dispositionNames('CON.foo.exe', 'text/plain');
attachmentNameAssert(
    $reservedAsciiName === '_CON.foo.txt' && $reservedUtf8Name === '_CON.foo.txt',
    'both Content-Disposition filename variants neutralize dotted device names'
);
attachmentNameAssert(
    AttachmentName::extensionForMime('application/pdf') === 'pdf' &&
        AttachmentName::extensionForMime('application/x-msdownload') === null,
    'only allow-listed MIME types receive canonical extensions'
);

echo "Attachment filename hardening tests passed.\n";
