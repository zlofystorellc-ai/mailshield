/*
 * ALL Gmail DOM selectors live here. Gmail ships obfuscated class names that change occasionally;
 * when detection stops working, update this file only (see GMAIL_SELECTORS.md).
 * Last verified against Gmail web (mail.google.com) desktop layout.
 */
(function (g) {
  'use strict';
  const MS = (g.MailShield = g.MailShield || {});

  MS.selectors = {
    // Root of the app; the MutationObserver watches this (falls back to document.body).
    appRoot: 'div[role="main"]',
    // One expanded message inside a conversation.
    messageContainer: 'div.adn',
    // The rendered body of an opened message (collapsed messages have no body node).
    messageBody: 'div.a3s',
    // Conversation subject heading.
    subject: 'h2.hP',
    // Sender chip; carries `email` and `name` attributes.
    sender: 'span.gD[email]',
    senderFallback: 'h3 span[email]',
    // Attachment chips: visible file name, and the element carrying `download_url="mime:filename:url"`.
    attachmentName: 'span.aV3',
    attachmentDownload: '[download_url]',
    // "Show details" header table (contains reply-to when present).
    headerDetailsRow: 'table.ajC tr',
    // Where the logged-in account is announced.
    accountButton: 'a[aria-label^="Google Account"]',
  };

  // Regexes used alongside the selectors.
  MS.selectorPatterns = {
    replyToLabel: /^\s*reply[- ]to\s*:?\s*$/i,
    emailInText: /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/,
    accountAria: /Google Account:\s*(.*?)\s*\(([^)]+@[^)]+)\)/,
  };
})(typeof globalThis !== 'undefined' ? globalThis : self);
