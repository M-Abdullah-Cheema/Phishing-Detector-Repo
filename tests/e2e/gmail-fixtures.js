/*
 * Gmail-like pages for the smoke test. The markup mirrors the nesting and class names of
 * Gmail's conversation view (header tables, span.gD sender, span.g2 recipients,
 * div.ii.gt > div.a3s body, attachment chips with download_url, collapsed messages).
 * Served at https://mail.google.com/mail/u/0/?pg=<name> via request interception.
 */
'use strict';

const THREAD_HASH = '#inbox/FMfcgzQXKwbcdLmnPqrsTvWxYz123456';

function attachmentChips(id, attachments) {
  if (!attachments.length) return '';
  const chips = attachments.map((a, i) => `
      <span class="aZo N5jrZb" download_url="${a.mime}:${a.name}:https://mail.google.com/mail/u/0?ui=2&amp;ik=1a2b3c&amp;attid=0.${i + 1}&amp;th=${id}&amp;disp=safe">
        <a class="aQy aZr e" href="#" target="_blank" role="link">
          <div class="aQw"><div class="aYv"><span class="aV3 zzV0ie">${a.name}</span></div><div class="SaH2Ve">${a.size}</div></div>
        </a>
      </span>`).join('');
  return `<div class="hq gt a10" role="list"><div class="aQH">${chips}</div></div>`;
}

function expandedMessage({ id, name, email, bodyHtml, attachments = [], bodyClass = 'a3s aiL' }) {
  return `
  <div role="listitem" aria-expanded="true">
    <div class="adn ads" data-message-id="#msg-f:${id}" data-legacy-message-id="${id.toString(16)}">
      <div class="gs">
        <div class="gE iv gt">
          <table cellpadding="0" class="cf gJ"><tbody>
            <tr class="acZ">
              <td class="gF gK"><table cellpadding="0" class="cf ix"><tbody><tr><td class="c2">
                <h3 class="iw gFxsud"><span class="qu" role="gridcell" tabindex="-1">
                  <span email="${email}" name="${name}" data-hovercard-id="${email}" class="gD"><span class="zF">${name}</span></span>
                  <span class="go"><span aria-hidden="true">&lt;</span>${email}<span aria-hidden="true">&gt;</span></span>
                </span></h3>
              </td></tr></tbody></table></td>
              <td class="gH bAk"><span class="g3" title="Wed, Nov 25, 2026, 10:42 AM" role="gridcell">10:42 AM</span></td>
            </tr>
            <tr class="acZ xD"><td colspan="3"><div class="iw ajw">
              <span class="hb">to <span email="student@gmail.com" name="me" data-hovercard-id="student@gmail.com" class="g2">me</span></span>
            </div></td></tr>
          </tbody></table>
        </div>
        <div class="utdU2e"></div>
        <div id=":${id}b" class="ii gt"><div id=":${id}c" class="${bodyClass}">${bodyHtml}</div></div>
        ${attachmentChips(id, attachments)}
      </div>
    </div>
  </div>`;
}

function collapsedMessage({ id, name, email, snippet }) {
  return `
  <div role="listitem" aria-expanded="false">
    <div class="kv"><div class="adf ads" data-legacy-message-id="${id.toString(16)}">
      <span email="${email}" name="${name}" class="gD"><span class="zF">${name}</span></span>
      <span class="iA g6">${snippet}</span>
    </div></div>
  </div>`;
}

function gmailPage({ title, subject, messages }) {
  return `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><title>${title}</title>
<style>
  body { font-family: Arial, sans-serif; margin: 0; background: #f6f8fc; }
  .nH[role="main"] { max-width: 900px; margin: 16px auto; background: #fff; border-radius: 16px; padding: 16px 24px; }
  .hP { font-size: 22px; font-weight: 400; }
  .adn { border-bottom: 1px solid #eee; padding: 8px 0 16px; }
  .gD { font-weight: 700; } .go, .g3, .hb { color: #5f6368; font-size: 12px; }
  .kv { padding: 10px 0; border-bottom: 1px solid #eee; color: #5f6368; }
  .ii { font-size: 14px; margin-top: 12px; }
  .aQH { display: flex; gap: 8px; margin-top: 12px; }
  .aZo { border: 1px solid #dadce0; border-radius: 8px; padding: 8px 12px; font-size: 13px; }
</style></head>
<body>
  <div class="nH"><div class="nH" role="main">
    <div class="ha"><h2 class="hP" data-thread-perm-id="thread-f:1781234567890" tabindex="-1">${subject}</h2></div>
    <div role="list" class="Bs nH">${messages.join('\n')}</div>
  </div></div>
</body></html>`;
}

const BENIGN = {
  id: 1781000000000001,
  name: 'GitHub',
  email: 'notifications@github.com',
  bodyHtml: `<div dir="ltr"><p><b>octocat</b> opened a pull request in org/repo.</p>
    <p>Add phishing heuristics for look-alike domains.</p>
    <p>&mdash;<br>Reply to this email directly, <a href="https://github.com/org/repo/pull/42" target="_blank">view it on GitHub</a>,
    or <a href="https://github.com/notifications/unsubscribe-auth/AAB" target="_blank">unsubscribe</a>.</p>
    <p><a href="https://github.com/org/repo/pull/42">https://github.com/org/repo/pull/42</a></p></div>`,
};

const SUSPICIOUS = {
  id: 1781000000000002,
  name: 'Amazon Support',
  email: 'amazon.support.team@gmail.com',
  bodyHtml: `<div dir="ltr"><p>Hello,</p><p>There was a problem processing your recent order #114-2233445.</p>
    <p>Please reply to this message with your order details so we can resolve it.</p><p>Amazon Customer Service</p></div>`,
};

const PHISHING = {
  id: 1781000000000003,
  name: 'PayPal Service',
  email: 'service@paypa1-security.com',
  bodyHtml: `<div dir="ltr"><table width="100%"><tr><td>
    <p>Dear Customer,</p>
    <p>We detected unusual activity on your account. Your account has been limited.</p>
    <p>Please verify your account within 24 hours or your account will be suspended.</p>
    <p><a href="http://paypa1-security.com/login" target="_blank"
          data-saferedirecturl="https://www.google.com/url?q=http://paypa1-security.com/login&amp;source=gmail&amp;ust=1">https://www.paypal.com/signin</a></p>
    <p>See the attached invoice for details.</p></td></tr></table></div>`,
  attachments: [{ name: 'PayPal_Invoice_2026.pdf.exe', mime: 'application/x-msdownload', size: '212 KB' }],
};

const THREAD_COLLAPSED = { id: 1781000000000010, name: 'Ali Raza', email: 'ali.raza@university.edu.pk', snippet: 'Can someone share the project files before Friday?' };

const THREAD_BENIGN = {
  id: 1781000000000011,
  name: 'Sara Ahmed',
  email: 'sara.ahmed@university.edu.pk',
  bodyHtml: `<div dir="ltr"><p>Hi all, here are the notes from today's meeting. I uploaded the slides to our shared folder.</p><p>Sara</p></div>`,
};

const THREAD_PHISHING = {
  id: 1781000000000012,
  name: 'IT Helpdesk',
  email: 'helpdesk@micros0ft-support.com',
  bodyHtml: `<div dir="ltr"><p>Your university mailbox storage is full. Your mailbox will be suspended within 24 hours.</p>
    <p>Confirm your password to keep receiving email:</p>
    <p><a href="http://45.77.12.9/owa/login.php" target="_blank">https://outlook.office.com/owa</a></p></div>`,
};

const RENAMED = {
  id: 1781000000000020,
  name: 'PayPal',
  email: 'alerts@paypa1-alerts.com',
};

function renamedMarkupPage() {
  // Same structure as a real message but with Gmail's obfuscated class names changed.
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><title>Verify now - student@gmail.com - Gmail</title></head><body>
  <div role="main"><div role="list"><div role="listitem">
    <div class="zz1" data-message-id="#msg-f:${RENAMED.id}">
      <h3 class="zz2"><span class="zz3" email="${RENAMED.email}" name="${RENAMED.name}">${RENAMED.name}</span></h3>
      <span class="zz4">to <span email="student@gmail.com" name="me">me</span></span>
      <div class="ii gt"><div class="zz5"><div dir="ltr"><p>Verify your account now.</p>
        <p><a href="http://paypa1-alerts.com/login">https://www.paypal.com</a></p></div></div></div>
    </div>
  </div></div></div></body></html>`;
}

const PAGES = {
  benign: () => gmailPage({ title: 'Inbox - student@gmail.com - Gmail', subject: '[org/repo] Add phishing heuristics (PR #42)', messages: [expandedMessage(BENIGN)] }),
  suspicious: () => gmailPage({ title: 'Inbox - student@gmail.com - Gmail', subject: 'Problem with your order', messages: [expandedMessage(SUSPICIOUS)] }),
  phishing: () => gmailPage({ title: 'Inbox - student@gmail.com - Gmail', subject: 'Urgent: Your account has been limited', messages: [expandedMessage(PHISHING)] }),
  thread: () => gmailPage({
    title: 'Re: Project files - student@gmail.com - Gmail',
    subject: 'Re: Project files',
    messages: [collapsedMessage(THREAD_COLLAPSED), expandedMessage(THREAD_BENIGN), expandedMessage(THREAD_PHISHING)],
  }),
  lazy: () => gmailPage({ title: 'Inbox - student@gmail.com - Gmail', subject: 'Urgent: Your account has been limited', messages: [expandedMessage({ ...PHISHING, id: 1781000000000030, bodyHtml: '' })] }),
  renamed: renamedMarkupPage,
};

module.exports = {
  THREAD_HASH,
  PAGES,
  MESSAGES: { BENIGN, SUSPICIOUS, PHISHING, THREAD_BENIGN, THREAD_PHISHING, RENAMED },
  expandedMessage,
};
