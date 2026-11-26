/*
 * Labeled evaluation set for tests/evaluate-metrics.js.
 *
 * `label` is the ground truth ("phishing" or "benign") decided by what the email is,
 * not by what PhishGuard happens to output. Several cases are deliberately hard
 * (no links, clean new domains, click-tracking newsletters) so the metrics are honest.
 * The unit-test fixtures in emails.js are reused, plus additional cases below.
 */
'use strict';

const unitFixtures = require('./emails.js');

const UNIT_FIXTURE_LABELS = {
  'PayPal credential phish with homoglyph domain and disguised link': 'phishing',
  'Microsoft 365 password-expiry phish linking to an IP address': 'phishing',
  'Invoice with executable disguised as PDF': 'phishing',
  'Display name contains a spoofed Apple address': 'phishing',
  'Amazon impersonation from free webmail': 'phishing',
  'Brand name hidden in the subdomain of an unrelated domain': 'phishing',
  'Punycode (IDN homograph) link': 'phishing',
  'Legitimate GitHub notification': 'benign',
  'Legitimate Google security alert': 'benign',
  'Newsletter with a shortened link stays below the warning threshold': 'benign',
  'Google redirect wrapper is unwrapped before checking': 'phishing',
};

const email = (sender, subject, bodyText, links = [], attachments = []) => ({
  subject,
  sender,
  bodyText,
  links: links.map(([text, href]) => ({ text, href })),
  attachments: attachments.map((name) => ({ name })),
});

const ADDITIONAL_PHISHING = [
  {
    name: 'DHL customs-fee parcel scam on a .top domain',
    category: 'delivery scam',
    email: email(
      { name: 'DHL Express', email: 'notice@dhl-tracking-info.top' },
      'Your parcel is on hold',
      'Your package could not be delivered. Pay the customs fee of $2.99 within 48 hours or it will be returned.',
      [['Track and pay', 'https://dhl-tracking-info.top/pay']],
    ),
  },
  {
    name: 'Netflix billing update on a look-alike domain',
    category: 'credential / payment theft',
    email: email(
      { name: 'Netflix', email: 'billing@netflix-account-update.com' },
      'Your membership is on hold',
      'We were unable to process your last payment. Update your payment details to avoid interruption of service.',
      [['Update account', 'https://netflix-account-update.com/billing']],
    ),
  },
  {
    name: 'HTML attachment posing as a remittance advice',
    category: 'credential theft (attachment)',
    email: email(
      { name: 'Accounts Payable', email: 'ap@vendor-invoices.net' },
      'Remittance advice - payment sent',
      'Please open the attached remittance and sign in with your login credentials to view the payment.',
      [],
      ['Remittance_Advice.html'],
    ),
  },
  {
    name: 'Business email compromise: gift-card request with no links',
    category: 'BEC / social engineering',
    email: email(
      { name: 'Dr. Ahmed (Head of Department)', email: 'hod.office.cs@gmail.com' },
      'Quick favour',
      'Are you available? I need you to buy gift cards urgently for a meeting. Reply with the codes as soon as possible.',
    ),
  },
  {
    name: 'OneDrive share hosted on a free hosting platform',
    category: 'credential theft',
    email: email(
      { name: 'OneDrive', email: 'share-noreply@docs-share.co' },
      'A file has been shared with you',
      'A document "Q4 Salary Review.xlsx" has been shared with you.',
      [['Open in OneDrive', 'https://onedrive-files.web.app/view?id=88123']],
    ),
  },
  {
    name: 'Coinbase account verification',
    category: 'credential theft',
    email: email(
      { name: 'Coinbase Support', email: 'security@coinbase-verify.com' },
      'Action required: verify your identity',
      'We noticed suspicious activity. Verify your identity to restore full access to your wallet.',
      [['Verify now', 'https://coinbase-verify.com/login']],
    ),
  },
  {
    name: 'IRS tax refund asking for SSN',
    category: 'identity theft',
    email: email(
      { name: 'IRS Refund Department', email: 'refund@irs-gov-refunds.com' },
      'You are eligible for a tax refund',
      'To receive your refund of $812.40, confirm your social security number and bank account details.',
      [['Claim refund', 'http://irs-gov-refunds.com/claim']],
    ),
  },
  {
    name: 'Instagram copyright notice with homoglyph sender',
    category: 'account takeover',
    email: email(
      { name: 'Instagram', email: 'copyright@lnstagram-help.com' },
      'Copyright infringement notice',
      'Your account will be closed within 24 hours due to a copyright complaint. Appeal here to keep your account.',
      [['Appeal', 'https://lnstagram-help.com/appeal']],
    ),
  },
  {
    name: 'Disk-image (.iso) attachment malware lure',
    category: 'malware delivery',
    email: email(
      { name: 'Shipping Docs', email: 'docs@freight-logistics.biz' },
      'Bill of lading',
      'Please find the shipping documents attached.',
      [],
      ['BL_Documents.iso'],
    ),
  },
  {
    name: 'HR policy lure on a clean, newly registered domain',
    category: 'credential theft (low signal)',
    email: email(
      { name: 'HR Department', email: 'hr@company-benefits-portal.com' },
      'Updated holiday policy',
      'Please review the updated holiday policy before the end of the month.',
      [['View policy', 'https://company-benefits-portal.com/policy']],
    ),
  },
  {
    name: 'Wells Fargo alert behind a URL shortener',
    category: 'credential theft',
    email: email(
      { name: 'Wells Fargo Online', email: 'alerts@wf-secure-mail.com' },
      'Unusual sign-in detected',
      'We noticed unusual activity on your account. Please verify your identity.',
      [['Review activity', 'https://bit.ly/3wfAlert']],
    ),
  },
];

const ADDITIONAL_BENIGN = [
  {
    name: 'University LMS deadline extension',
    category: 'academic',
    email: email(
      { name: 'LMS Notifications', email: 'noreply@lms.university.edu.pk' },
      'Assignment 3 deadline extended',
      'The deadline for Assignment 3 has been extended to Friday. Submit through the course page.',
      [['Open course page', 'https://lms.university.edu.pk/course/view.php?id=231']],
    ),
  },
  {
    name: 'Bank one-time password (legitimate OTP)',
    category: 'transactional',
    email: email(
      { name: 'HBL Alerts', email: 'alerts@hbl.com' },
      'Your login code',
      'Your OTP for internet banking login is 482910. Never share this code with anyone.',
    ),
  },
  {
    name: 'Amazon shipping confirmation',
    category: 'transactional',
    email: email(
      { name: 'Amazon.com', email: 'shipment-tracking@amazon.com' },
      'Your package has shipped',
      'Your order of "Network Security Essentials" has shipped and will arrive Thursday.',
      [['Track package', 'https://www.amazon.com/progress-tracker/package?orderId=114-22'], ['amazon.com/orders', 'https://www.amazon.com/gp/your-account/order-history']],
    ),
  },
  {
    name: 'LinkedIn job alert',
    category: 'notification',
    email: email(
      { name: 'LinkedIn Job Alerts', email: 'jobalerts-noreply@linkedin.com' },
      '5 new jobs for "Security Analyst"',
      'New jobs matching your preferences in Lahore.',
      [['See all jobs', 'https://www.linkedin.com/jobs/search/?keywords=security%20analyst']],
    ),
  },
  {
    name: 'Mailchimp newsletter with click-tracking links',
    category: 'marketing (known false-positive pattern)',
    email: email(
      { name: 'Bean There Coffee', email: 'hello@beantherecoffee.com' },
      'New autumn menu',
      'Our autumn menu is here. Visit us this weekend.',
      [['www.beantherecoffee.com', 'https://beantherecoffee.us12.list-manage.com/track/click?u=abc&id=def']],
    ),
  },
  {
    name: 'Microsoft password-changed notice (real)',
    category: 'security notification',
    email: email(
      { name: 'Microsoft account team', email: 'account-security-noreply@accountprotection.microsoft.com' },
      'Your password changed',
      'The password for the Microsoft account st***@outlook.com was changed. If this was you, you can safely ignore this email.',
      [['Review recent activity', 'https://account.live.com/activity']],
    ),
  },
  {
    name: 'Classmate sharing a project archive',
    category: 'personal',
    email: email(
      { name: 'Hamza Khan', email: 'hamza.khan.cs@gmail.com' },
      'Project source code',
      'Here is the source code for our IS project, unzip and run npm test.',
      [],
      ['phishguard-src.zip'],
    ),
  },
  {
    name: 'Dropbox shared folder',
    category: 'notification',
    email: email(
      { name: 'Dropbox', email: 'no-reply@dropbox.com' },
      'Sara shared "Lab Reports" with you',
      'Sara Ahmed invited you to view the folder "Lab Reports".',
      [['Go to folder', 'https://www.dropbox.com/scl/fo/abc123']],
    ),
  },
  {
    name: 'Google Calendar invitation',
    category: 'notification',
    email: email(
      { name: 'Google Calendar', email: 'calendar-notification@google.com' },
      'Invitation: IS project viva @ Mon 1 Dec 10am',
      'You have been invited to the following event. Join with Google Meet.',
      [['meet.google.com/abc-defg-hij', 'https://meet.google.com/abc-defg-hij']],
      ['invite.ics'],
    ),
  },
  {
    name: 'IT maintenance notice with mild urgency',
    category: 'internal notice',
    email: email(
      { name: 'University IT Services', email: 'it@university.edu.pk' },
      'Scheduled maintenance tonight',
      'Action required: please save your work before 11 PM. The portal will be offline for two hours.',
    ),
  },
  {
    name: 'PayPal payment receipt (real)',
    category: 'transactional',
    email: email(
      { name: 'PayPal', email: 'service@paypal.com' },
      'Receipt for your payment to Udemy',
      'You sent a payment of $12.99 USD to Udemy. Transaction ID 7XY12345AB.',
      [['View transaction', 'https://www.paypal.com/myaccount/transactions/details/7XY12345AB']],
    ),
  },
  {
    name: 'Local e-commerce order confirmation',
    category: 'transactional',
    email: email(
      { name: 'Daraz', email: 'no-reply@daraz.pk' },
      'Order #4021 confirmed',
      'Thank you for your order. We will notify you when it ships.',
      [['View order', 'https://my.daraz.pk/customer/order/index/']],
    ),
  },
  {
    name: 'Marketing email with shortener and "limited time" wording',
    category: 'marketing',
    email: email(
      { name: 'Coursera', email: 'no-reply@m.learn.coursera.org' },
      'Limited time: 40% off Coursera Plus',
      'Learn cybersecurity with industry certificates. Offer ends Sunday.',
      [['Claim offer', 'https://bit.ly/coursera-plus-40']],
    ),
  },
  {
    name: 'Airline e-ticket with HTML attachment',
    category: 'transactional',
    email: email(
      { name: 'PIA Reservations', email: 'eticket@piac.com.pk' },
      'Your e-ticket: LHE-KHI',
      'Your booking is confirmed. Your e-ticket is attached.',
      [],
      ['eticket_LHE_KHI.html'],
    ),
  },
];

const fromUnitFixtures = unitFixtures.map((f) => {
  const label = UNIT_FIXTURE_LABELS[f.name];
  if (!label) throw new Error(`No ground-truth label for unit fixture "${f.name}"`);
  return { name: f.name, label, category: 'unit-test fixture', email: f.email };
});

module.exports = [
  ...fromUnitFixtures,
  ...ADDITIONAL_PHISHING.map((c) => ({ ...c, label: 'phishing' })),
  ...ADDITIONAL_BENIGN.map((c) => ({ ...c, label: 'benign' })),
];
