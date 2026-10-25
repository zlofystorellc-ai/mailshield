/* Test fixtures: scam variants, genuine bank alerts, and ordinary emails. All data is fictional. */

// Five variants of the "₹X credited / sent by mistake, please refund" scam:
// different amounts, names, senders and wording. Once a signature is active, ALL must match it.
const fakeCreditVariants = [
  {
    senderName: 'Rakesh Kumar', senderEmail: 'rakesh.k1987@gmail.com',
    subject: 'Money sent by mistake to your account',
    body: `Dear Rahul,
Rs. 25,000 has been credited to your bank account by mistake from my UPI. Please refund the amount immediately to my UPI ID rakesh1987@okaxis.
I need this money urgently for my mother's hospital bill. Call me on +91 98765 43210 after you send it back.
Thanks, Rakesh`,
  },
  {
    senderName: 'Sunita Sharma', senderEmail: 'sunita.sharma.help@yahoo.com',
    subject: 'Wrong transfer - please return',
    body: `Hello Priya,
I have transferred ₹12,500 to your account by mistake today. Kindly refund the money immediately to my UPI sunita55@ybl.
It was meant for my brother. Please do it urgently, call me on 9123456780 when done.
Regards, Sunita`,
  },
  {
    senderName: 'Amit Verma', senderEmail: 'amitverma.pay@outlook.com',
    subject: 'Payment credited by mistake',
    body: `Hi Ankit,
INR 8,000 was credited to your account by mistake from my side. Please refund the amount immediately on my UPI amitv@paytm otherwise I will file a police complaint.
Contact me on +91 99887 76655 urgently.
Thanks, Amit`,
  },
  {
    senderName: 'Pooja', senderEmail: 'pooja.refund2024@gmail.com',
    subject: 'Galti se paise bhej diye',
    body: `Namaste Suresh ji,
Maine galti se aapke account mein Rs 15000 bhej diye hain. Please refund kar do turant, mera UPI hai pooja2024@oksbi.
Bahut zaroori hai, money urgently chahiye. Call karo 9988776655 par.
Dhanyavaad, Pooja`,
  },
  {
    senderName: 'Vikram Singh', senderEmail: 'vikram.singh.upi@gmail.com',
    subject: 'Sent money to wrong account',
    body: `Dear Neha,
By mistake I sent ₹40,000 to your bank account yesterday. Please refund the amount immediately to my UPI vikram.s@okicici, it was for my rent.
This is urgent, please call me at +91 90000 12345 once you send it back.
Thanks, Vikram`,
  },
];

const otherScams = {
  kyc: {
    senderName: 'SBI Bank', senderEmail: 'sbi-alerts@sbi-kyc-update.xyz',
    subject: 'Your SBI account will be blocked today',
    body: 'Dear customer, your KYC has expired. Your account will be blocked within 24 hours. Update your KYC now by clicking the link below.',
    links: [{ text: 'https://www.onlinesbi.sbi/kyc', href: 'http://sbi-kyc-update.xyz/login' }],
  },
  kycHinglish: {
    senderName: 'HDFC Bank', senderEmail: 'hdfc.care.desk@gmail.com',
    subject: 'KYC update karo',
    body: 'Aapka KYC pending hai. Turant update karo warna account band ho jayega. Link par click karke PAN aur Aadhaar details bharein.',
    links: [{ text: 'Update KYC', href: 'https://hdfcbank-kyc.top/update' }],
  },
  lottery: {
    senderName: 'Lucky Draw Team', senderEmail: 'winner@lucky-prize.click',
    subject: 'Congratulations! You have won ₹25,00,000',
    body: 'Congratulations, you have won ₹25,00,000 in the KBC lucky draw. Claim your prize now by paying a small processing fee of Rs 4,999. Contact our manager on WhatsApp +91 70000 11111.',
    links: [{ text: 'Claim now', href: 'https://bit.ly/claim-kbc' }],
  },
  fakeJob: {
    senderName: 'HR Recruitment', senderEmail: 'hr.jobs.india@gmail.com',
    subject: 'Part time job - earn ₹5000 daily',
    body: 'Work from home part-time job. Earn ₹5000 per day by liking YouTube videos. Task-based work, daily payout. Pay a registration fee of Rs 999 to start. Join our telegram group.',
    links: [{ text: 'Join now', href: 'https://t.ly/job123' }],
  },
  delivery: {
    senderName: 'India Post', senderEmail: 'support@indiapost-track.buzz',
    subject: 'Your parcel is on hold',
    body: 'Your parcel is on hold due to an incomplete address. Pay a redelivery fee of Rs 25 within 12 hours or it will be returned.',
    links: [{ text: 'Pay fee', href: 'https://indiapost-track.buzz/pay' }],
  },
  otp: {
    senderName: 'Paytm Support', senderEmail: 'paytm.support.team@gmail.com',
    subject: 'Cashback verification',
    body: 'To receive your cashback of ₹2,000 please share the OTP you just received with our executive. Reply with your OTP immediately.',
  },
  otpHinglish: {
    senderName: 'Customer Care', senderEmail: 'care@refund-desk.top',
    subject: 'Refund ke liye OTP',
    body: 'Aapka refund pending hai. Jo OTP aaya hai woh batao turant, warna refund cancel ho jayega.',
  },
  malwareAttachment: {
    senderName: 'Accounts', senderEmail: 'accounts@vendor-billing.com',
    subject: 'Invoice attached',
    body: 'Please find the invoice attached.',
    attachments: ['Invoice_2291.pdf.exe'],
  },
};

// Loan-recovery pressure from a look-alike lender domain with a hidden short link (seen in a real Gmail spam folder).
otherScams.loanRecovery = {
  senderName: '', senderEmail: 'credit-reportupdates@mpokketreporting.com',
  subject: 'Urgent Notice: Reporting Overdue Loan to Credit Bureaus',
  body: 'Dear Customer, We are writing to inform you regarding your overdue loan(s). We are obligated to report this information to the credit bureaus. '
    + 'Days Past Due: 44. Please reach out to our customer services team at 9000000000. Please note that it is crucial to address these overdue payments '
    + 'promptly to minimize any potential negative impact on your credit score. You may also clear your outstanding dues by paying through this repayment link.',
  links: [{ text: 'this repayment link', href: 'https://mpkt.to/MPOKKT/abc_def' }],
};

// The same lender writing from its real domain with its real link -> no look-alike / short-link warning.
const genuineLenderReminder = {
  senderName: 'mPokket', senderEmail: 'noreply@mpokket.com',
  subject: 'Your EMI is due soon',
  body: 'Hi, your EMI is due on the 5th. Pay on time to keep a good credit score. Open the mPokket app to pay.',
  links: [{ text: 'Pay now', href: 'https://www.mpokket.com/pay' }],
};

// Genuine transaction alerts from verified bank domains -> must NOT be flagged.
const genuineBankAlerts = [
  {
    senderName: 'HDFC Bank InstaAlerts', senderEmail: 'alerts@hdfcbank.net',
    subject: '❗ You have done a UPI txn. Check details!',
    body: `Dear Customer,
Rs.5000.00 has been credited to account **4521 on 12-05-25. UPI Ref No 512345678901.
Never share your OTP, PIN or password with anyone. If you did not authorise this transaction, call 18002026161 immediately.
Warm Regards,
HDFC Bank`,
    links: [{ text: 'hdfcbank.com', href: 'https://www.hdfcbank.com/personal/need-help' }],
  },
  {
    senderName: 'State Bank of India', senderEmail: 'donotreply.sbiatm@alerts.sbi.co.in',
    subject: 'Transaction alert',
    body: 'Dear Customer, your A/c XXXXX1234 is debited for Rs. 2,500.00 on 10Jan25 by UPI. If not done by you, call 1800 1234 to block UPI. Do not share OTP with anyone. - SBI',
  },
  {
    senderName: 'ICICI Bank', senderEmail: 'credit_cards@icicibank.com',
    subject: 'Refund credited',
    body: 'Dear Customer, a refund of INR 1,299.00 has been credited to your ICICI Bank Credit Card XX5678. Please do not share your OTP or CVV with anyone.',
    links: [{ text: 'Login to iMobile', href: 'https://www.icicibank.com/mobile-banking' }],
  },
];

// Normal personal and work emails -> SAFE.
const normalEmails = [
  {
    senderName: 'Mom', senderEmail: 'sunita.mehta1962@gmail.com',
    subject: 'Dinner on Sunday?',
    body: 'Hi beta, are you coming home this Sunday? Papa wants to make biryani. Let me know by Friday. Love, Mom',
  },
  {
    senderName: 'Arjun Rao', senderEmail: 'arjun.rao@acmecorp.com',
    subject: 'Q3 planning deck',
    body: 'Hi team, I have shared the Q3 planning deck on the drive. Please review the budget slide before our meeting on Thursday at 3 pm. Thanks, Arjun',
    links: [{ text: 'Q3 Planning', href: 'https://docs.google.com/presentation/d/abc123/edit' }],
    attachments: ['Q3_plan.pdf'],
  },
  {
    senderName: 'GitHub', senderEmail: 'noreply@github.com',
    subject: '[acme/web] Pull request merged',
    body: 'Merged #482 into main. View it on GitHub.',
    links: [{ text: 'View it on GitHub', href: 'https://github.com/acme/web/pull/482' }],
  },
  {
    senderName: 'Priya (Finance)', senderEmail: 'priya@acmecorp.com',
    subject: 'Reimbursement processed',
    body: 'Hi, your travel reimbursement of ₹3,450 has been processed and will be credited with this month\'s salary. Regards, Priya',
  },
  {
    senderName: 'Rohit', senderEmail: 'rohit.k@gmail.com',
    subject: 'Trip photos',
    body: 'Hey! Uploaded the Goa trip photos, check them out. Call me on 9876501234 when you are free.',
    links: [{ text: 'Photos', href: 'https://photos.app.goo.gl/xyz' }],
  },
];

module.exports = { fakeCreditVariants, otherScams, genuineBankAlerts, genuineLenderReminder, normalEmails };
