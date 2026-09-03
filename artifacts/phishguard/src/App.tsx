import { FormEvent, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  FileWarning,
  Globe2,
  Inbox,
  Info,
  Link2,
  LockKeyhole,
  MessageCircle,
  RotateCcw,
  ScanSearch,
  ShieldCheck,
  ShieldEllipsis,
  Sparkles,
  Upload,
  UserRound,
  X,
} from 'lucide-react';

type ScanType = 'email' | 'message' | 'url' | 'attachment';
type RiskLevel = 'low' | 'medium' | 'suspicious' | 'high';

type Finding = {
  title: string;
  detail: string;
  tone: 'high' | 'medium' | 'clear';
};

type Analysis = {
  score: number;
  level: RiskLevel;
  findings: Finding[];
  recommendations: string[];
  checkedLabel: string;
};

const scanTypes: Array<{
  id: ScanType;
  label: string;
  hint: string;
  icon: typeof Inbox;
}> = [
  { id: 'email', label: 'Email', hint: 'Paste an email', icon: Inbox },
  { id: 'message', label: 'SMS / WhatsApp', hint: 'Paste a message', icon: MessageCircle },
  { id: 'url', label: 'URL', hint: 'Check a link', icon: Globe2 },
  { id: 'attachment', label: 'Attachment', hint: 'Check a filename', icon: FileWarning },
];

const examples: Record<ScanType, string> = {
  email:
    'From: DBS Bank <security@dbs-secure-login.com>\nSubject: URGENT: Your account will be suspended\n\nYour account has been compromised. Please verify your account immediately by clicking the link below.\n\nhttp://dbs-secure-login.com/verify\n\nPlease enter your username, password and OTP.',
  message:
    'Congratulations! You have won a $500 shopping voucher!\n\nClick below to claim your prize:\nhttp://sg-reward-claim.com\n\nOffer expires today!',
  url: 'https://paypa1-secure-login.com/verify',
  attachment: 'Invoice_August.pdf.exe',
};

const defaultCopy: Record<ScanType, { title: string; placeholder: string }> = {
  email: {
    title: 'Paste the suspicious email',
    placeholder: 'Include the sender, subject, and message body for a more useful check...',
  },
  message: {
    title: 'Paste the suspicious message',
    placeholder: 'Paste the SMS or WhatsApp message, including any links...',
  },
  url: {
    title: 'Enter a URL to check',
    placeholder: 'https://example.com/verify',
  },
  attachment: {
    title: 'Enter the attachment filename',
    placeholder: 'For example: Invoice_August.pdf.exe',
  },
};

function riskForScore(score: number): RiskLevel {
  if (score <= 20) return 'low';
  if (score <= 40) return 'medium';
  if (score <= 60) return 'suspicious';
  return 'high';
}

function riskLabel(level: RiskLevel) {
  return {
    low: 'Low risk',
    medium: 'Medium risk',
    suspicious: 'Suspicious',
    high: 'High risk',
  }[level];
}

function uniqueUrls(value: string) {
  return value.match(/https?:\/\/[^\s<>"')]+/gi) ?? [];
}

function getUrlFindings(value: string): { findings: Finding[]; score: number } {
  const url = value.trim();
  if (!url) return { findings: [], score: 0 };
  const findings: Finding[] = [];
  let score = 0;
  let parsed: URL | null = null;
  try {
    parsed = new URL(url.includes('://') ? url : `https://${url}`);
  } catch {
    findings.push({
      title: 'Malformed URL',
      detail: 'This does not look like a complete web address. Avoid opening it until you can verify the exact destination.',
      tone: 'high',
    });
    return { findings, score: 35 };
  }
  const host = parsed.hostname.toLowerCase();
  if (parsed.protocol !== 'https:') {
    score += 15;
    findings.push({
      title: 'No secure connection',
      detail: 'The link uses HTTP instead of HTTPS. Encryption alone does not make a site safe, but its absence is worth noticing.',
      tone: 'medium',
    });
  } else {
    findings.push({
      title: 'HTTPS is present',
      detail: 'The connection is encrypted. Remember that HTTPS does not prove that the website is legitimate.',
      tone: 'clear',
    });
  }
  if (host.length > 28 || parsed.pathname.length > 36) {
    score += 10;
    findings.push({
      title: 'Unusually long address',
      detail: 'Long addresses can hide the important part of a link among extra words, paths, or tracking parameters.',
      tone: 'medium',
    });
  }
  if (/(login|verify|secure|account|update|payment|claim|reward|wallet)/i.test(url)) {
    score += 15;
    findings.push({
      title: 'Sensitive action keywords',
      detail: 'Words such as “login”, “verify”, or “secure” can be used to make a link feel official and prompt a quick click.',
      tone: 'medium',
    });
  }
  if (/\b\d{1,3}(?:\.\d{1,3}){3}\b/.test(host)) {
    score += 25;
    findings.push({
      title: 'IP address used as destination',
      detail: 'This link points directly to an IP address instead of a recognizable domain. That is uncommon for legitimate customer services.',
      tone: 'high',
    });
  }
  if (/(paypa1|micros0ft|faceb00k|g00gle|amaz0n|appleid|secure-login|account-verify)/i.test(host) || /xn--/i.test(host)) {
    score += 30;
    findings.push({
      title: 'Lookalike or suspicious domain',
      detail: `The domain “${host}” appears designed to resemble a trusted service or uses an unusual spelling.`,
      tone: 'high',
    });
  }
  if (parsed.username || parsed.port || /@/.test(url)) {
    score += 20;
    findings.push({
      title: 'Obscured destination',
      detail: 'The URL contains a sign-in or port detail that can make the real destination harder to spot.',
      tone: 'high',
    });
  }
  if (!findings.some((finding) => finding.tone !== 'clear')) {
    findings.push({
      title: 'No obvious URL red flags',
      detail: 'No common warning signs were found in this quick check. Still confirm the domain before signing in.',
      tone: 'clear',
    });
  }
  return { findings, score: Math.min(score, 100) };
}

function analyseContent(type: ScanType, value: string): Analysis {
  const text = value.trim();
  const findings: Finding[] = [];
  let score = 0;
  const urls = uniqueUrls(text);
  const add = (finding: Finding, points: number) => {
    findings.push(finding);
    score += points;
  };

  if (type === 'attachment') {
    const filename = text.split(/[\\/]/).pop() ?? text;
    const extension = filename.match(/\.([a-z0-9]+)$/i)?.[1]?.toLowerCase() ?? '';
    const hasDoubleExtension = /\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|bat|cmd|com|pif)$/i.test(filename);
    if (hasDoubleExtension) {
      add(
        {
          title: 'Double file extension',
          detail: `“${filename}” looks like a document at first glance, but its actual extension is .${extension}. This trick can disguise an executable file.`,
          tone: 'high',
        },
        40,
      );
    }
    if (['exe', 'scr', 'js', 'vbs', 'bat', 'cmd', 'com', 'pif'].includes(extension)) {
      add(
        {
          title: 'Potentially dangerous file type',
          detail: `.${extension} files can run code on your device. Do not open this attachment unless you have independently verified the sender and file.`,
          tone: 'high',
        },
        35,
      );
    } else if (['zip', 'rar', '7z'].includes(extension)) {
      add(
        {
          title: 'Archive file detected',
          detail: 'Compressed files can contain executable or malicious files. Treat unexpected archives with extra caution.',
          tone: 'medium',
        },
        20,
      );
    } else if (['docm', 'xlsm', 'pptm'].includes(extension)) {
      add(
        {
          title: 'Macro-enabled document',
          detail: 'This document type can contain macros that run code. Never enable macros in an unexpected file.',
          tone: 'high',
        },
        30,
      );
    } else if (extension) {
      findings.push({
        title: `.${extension} file`,
        detail: 'The extension is not automatically dangerous, but the sender and context still matter.',
        tone: 'clear',
      });
    } else {
      add(
        {
          title: 'Unknown file type',
          detail: 'The filename does not show a recognizable extension. Do not open files when you cannot verify what they are.',
          tone: 'medium',
        },
        20,
      );
    }
    if (!findings.some((finding) => finding.tone !== 'clear')) {
      findings.push({
        title: 'No obvious filename red flags',
        detail: 'This quick check only inspects the name and extension. It does not open or execute the file.',
        tone: 'clear',
      });
    }
    return {
      score: Math.min(score, 100),
      level: riskForScore(Math.min(score, 100)),
      findings,
      recommendations: [
        'Do not open an unexpected attachment.',
        'Confirm the sender through a separate channel.',
        'If it is work-related, forward it to your organisation’s security team.',
      ],
      checkedLabel: filename,
    };
  }

  if (type === 'url') {
    const urlResult = getUrlFindings(text);
    return {
      score: urlResult.score,
      level: riskForScore(urlResult.score),
      findings: urlResult.findings,
      recommendations: [
        'Do not sign in or enter payment details through this link.',
        'Open the organisation’s official website by typing its address yourself.',
        'If you already entered information, change the password from the official site.',
      ],
      checkedLabel: text,
    };
  }

  if (/(urgent|immediately|within \d+ hours?|expires? today|last chance|act now|as soon as possible)/i.test(text)) {
    add(
      {
        title: 'Urgent or pressuring language',
        detail: 'Scammers create time pressure so you act before you have time to verify the request.',
        tone: 'high',
      },
      15,
    );
  }
  if (/(suspend|blocked|compromised|closed|unauthori[sz]ed|security alert|will be terminated)/i.test(text)) {
    add(
      {
        title: 'Threat of account or service loss',
        detail: 'Threats about suspension or compromise are commonly used to make a message feel immediate and alarming.',
        tone: 'high',
      },
      15,
    );
  }
  if (/(password|passcode|username|login details|credit card|bank details|personal information)/i.test(text)) {
    add(
      {
        title: 'Requests sensitive information',
        detail: 'Legitimate organisations generally do not ask for passwords, full card details, or login information through an unsolicited message.',
        tone: 'high',
      },
      20,
    );
  }
  if (/\bOTP\b|one[- ]time pass(code)?|verification code/i.test(text)) {
    add(
      {
        title: 'OTP or verification code request',
        detail: 'Never disclose a one-time code to someone who contacts you unexpectedly. A legitimate support agent should not need it.',
        tone: 'high',
      },
      20,
    );
  }
  if (/(won|winner|congratulations|voucher|prize|reward|cashback|free gift|\$\d+)/i.test(text)) {
    add(
      {
        title: 'Too-good-to-be-true reward',
        detail: 'Unexpected prizes and rewards are often used as a lure to get people to click before checking the sender.',
        tone: 'medium',
      },
      15,
    );
  }
  if (urls.length) {
    const [firstUrl] = urls;
    const urlResult = getUrlFindings(firstUrl ?? '');
    if (urlResult.score > 0) {
      add(
        {
          title: 'Suspicious link included',
          detail: 'The message includes a link with warning signs. Links can lead to fake sign-in pages or malware.',
          tone: 'high',
        },
        Math.min(25, Math.max(15, Math.round(urlResult.score / 2))),
      );
    }
  }
  if (type === 'email' && /from:\s*.+<([^>]+)>/i.test(text)) {
    const email = text.match(/from:\s*.+<([^>]+)>/i)?.[1] ?? '';
    const domain = email.split('@')[1] ?? '';
    if (/(secure|support|alert|verify|login|mail-)/i.test(domain) || !domain.includes('.')) {
      add(
        {
          title: 'Sender domain deserves checking',
          detail: `The sender domain “${domain}” does not clearly match a known organisation and may be impersonating one.`,
          tone: 'high',
        },
        20,
      );
    } else {
      findings.push({
        title: 'Sender address included',
        detail: 'A sender address was found. Compare its domain letter-by-letter with the organisation’s official domain.',
        tone: 'clear',
      });
    }
  }
  if (!findings.length) {
    findings.push({
      title: 'No common warning signs found',
      detail: 'This quick check did not find common phishing indicators. Stay cautious with unexpected requests and links.',
      tone: 'clear',
    });
  }
  const finalScore = Math.min(score, 100);
  return {
    score: finalScore,
    level: riskForScore(finalScore),
    findings,
    recommendations: [
      'Pause before clicking or replying.',
      'Verify the request using a trusted website or phone number.',
      'Never share passwords, card details, or one-time codes.',
    ],
    checkedLabel: type === 'email' ? 'Email content' : 'Message content',
  };
}

function App() {
  const [activeType, setActiveType] = useState<ScanType>('email');
  const [value, setValue] = useState('');
  const [analysis, setAnalysis] = useState<Analysis | null>(null);
  const [isAnalysing, setIsAnalysing] = useState(false);
  const activeCopy = defaultCopy[activeType];
  const activeScan = scanTypes.find((scan) => scan.id === activeType)!;
  const highCount = useMemo(
    () => analysis?.findings.filter((finding) => finding.tone === 'high').length ?? 0,
    [analysis],
  );

  const selectType = (type: ScanType) => {
    setActiveType(type);
    setValue('');
    setAnalysis(null);
  };

  const runAnalysis = (event?: FormEvent) => {
    event?.preventDefault();
    if (!value.trim()) return;
    setIsAnalysing(true);
    window.setTimeout(() => {
      setAnalysis(analyseContent(activeType, value));
      setIsAnalysing(false);
    }, 420);
  };

  const loadExample = () => {
    setValue(examples[activeType]);
    setAnalysis(null);
  };

  return (
    <div className="app-shell">
      <header className="topbar">
        <div className="brand-lockup">
          <div className="brand-mark"><ShieldCheck size={21} strokeWidth={2.4} /></div>
          <div>
            <div className="brand-name">PhishGuard</div>
            <div className="brand-caption">Pause. Check. Stay safe.</div>
          </div>
        </div>
        <div className="topbar-note"><LockKeyhole size={14} /> Analysis happens in your browser</div>
      </header>

      <main className="page-content">
        <section className="intro">
          <div>
            <p className="eyebrow"><span className="eyebrow-dot" /> Phishing awareness tool</p>
            <h1>Not sure if it’s safe?<br /><em>Check before you click.</em></h1>
            <p className="intro-copy">
              Paste a suspicious email, message, link, or attachment filename.
              PhishGuard will point out the signals worth a second look.
            </p>
          </div>
          <div className="intro-badge">
            <ShieldEllipsis size={25} />
            <span><strong>Built for learning</strong><br />Clear signals, not scary verdicts</span>
          </div>
        </section>

        <section className="workspace-grid">
          <div className="scan-panel panel">
            <div className="panel-heading">
              <div>
                <p className="section-kicker">Start a check</p>
                <h2>What would you like to analyse?</h2>
              </div>
              <span className="step-count">01 / 02</span>
            </div>

            <div className="scan-type-grid">
              {scanTypes.map((scan) => {
                const Icon = scan.icon;
                return (
                  <button
                    type="button"
                    key={scan.id}
                    className={`scan-type ${activeType === scan.id ? 'active' : ''}`}
                    onClick={() => selectType(scan.id)}
                    aria-pressed={activeType === scan.id}
                  >
                    <span className="scan-icon"><Icon size={19} /></span>
                    <span className="scan-type-label">{scan.label}</span>
                    <span className="scan-type-hint">{scan.hint}</span>
                    {activeType === scan.id && <Check className="selected-check" size={15} />}
                  </button>
                );
              })}
            </div>

            <form onSubmit={runAnalysis}>
              <div className="input-heading">
                <label htmlFor="scan-input">{activeCopy.title}</label>
                <button type="button" className="text-button" onClick={loadExample}>
                  <Sparkles size={14} /> Try an example
                </button>
              </div>
              <div className={`textarea-wrap ${activeType === 'attachment' ? 'filename-input' : ''}`}>
                {activeType === 'attachment' ? <Upload size={19} /> : <ScanSearch size={19} />}
                <textarea
                  id="scan-input"
                  rows={activeType === 'attachment' || activeType === 'url' ? 2 : 6}
                  value={value}
                  onChange={(event) => {
                    setValue(event.target.value);
                    setAnalysis(null);
                  }}
                  placeholder={activeCopy.placeholder}
                  spellCheck={activeType !== 'url' && activeType !== 'attachment'}
                />
                {value && (
                  <button className="clear-button" type="button" aria-label="Clear input" onClick={() => setValue('')}>
                    <X size={16} />
                  </button>
                )}
              </div>
              <div className="form-footer">
                <span className="privacy-note"><LockKeyhole size={13} /> Nothing is uploaded or stored</span>
                <button className="primary-button" type="submit" disabled={!value.trim() || isAnalysing}>
                  {isAnalysing ? 'Checking...' : 'Analyse safely'} <ArrowRight size={17} />
                </button>
              </div>
            </form>
          </div>

          <aside className="learn-panel">
            <div className="learn-illustration">
              <div className="orbit orbit-one" />
              <div className="orbit orbit-two" />
              <div className="shield-orb"><ShieldCheck size={39} /></div>
              <div className="orbit-dot dot-one" />
              <div className="orbit-dot dot-two" />
            </div>
            <p className="section-kicker">How it works</p>
            <h3>A second pair of eyes for suspicious messages.</h3>
            <p>PhishGuard checks common patterns like urgency, sensitive requests, lookalike domains, and risky file extensions.</p>
            <div className="learn-divider" />
            <div className="mini-rule"><span className="mini-icon"><Info size={15} /></span><span><strong>Educational, not definitive</strong><br />A low score never guarantees a message is safe.</span></div>
          </aside>
        </section>

        {analysis && (
          <section className="results-section" aria-live="polite">
            <div className="result-header">
              <div>
                <p className="section-kicker">Analysis complete</p>
                <h2>Here’s what PhishGuard noticed</h2>
              </div>
              <button type="button" className="secondary-button" onClick={() => { setAnalysis(null); setValue(''); }}>
                <RotateCcw size={15} /> New analysis
              </button>
            </div>
            <div className={`result-summary ${analysis.level}`}>
              <div className="score-ring" style={{ '--score-angle': `${analysis.score * 3.6}deg` } as React.CSSProperties}>
                <div><strong>{analysis.score}</strong><span>/100</span></div>
              </div>
              <div className="summary-copy">
                <p className="section-kicker">Phishing risk score</p>
                <h3>{riskLabel(analysis.level)}</h3>
                <p>{analysis.score >= 61 ? 'Several strong warning signs were found. Treat this as unsafe until independently verified.' : analysis.score >= 41 ? 'Some characteristics deserve a closer look before you interact with it.' : 'No strong warning signs stood out in this quick check.'}</p>
              </div>
              <div className="summary-meta"><span>{analysis.checkedLabel}</span><span>{highCount} strong {highCount === 1 ? 'signal' : 'signals'}</span></div>
            </div>

            <div className="result-columns">
              <div className="result-card">
                <div className="result-card-title"><AlertTriangle size={17} /><h3>Red flags</h3><span>{analysis.findings.length} found</span></div>
                <div className="finding-list">
                  {analysis.findings.map((finding) => (
                    <div className="finding" key={finding.title}>
                      <span className={`finding-icon ${finding.tone}`}>{finding.tone === 'clear' ? <Check size={14} /> : <AlertTriangle size={14} />}</span>
                      <div><strong>{finding.title}</strong><p>{finding.detail}</p></div>
                    </div>
                  ))}
                </div>
              </div>
              <div className="result-card why-card">
                <div className="result-card-title"><Info size={17} /><h3>What should I do?</h3></div>
                <p className="why-lede">The safest next step is to slow down and verify the request somewhere you trust.</p>
                <ul className="recommendation-list">
                  {analysis.recommendations.map((recommendation, index) => (
                    <li key={recommendation}><span>{index + 1}</span>{recommendation}</li>
                  ))}
                </ul>
                <div className="remember-box"><UserRound size={15} /><span><strong>Remember:</strong> legitimate organisations will not rush you into sharing secrets.</span></div>
              </div>
            </div>
          </section>
        )}

        {!analysis && (
          <section className="footer-tip">
            <div className="tip-icon"><Link2 size={17} /></div>
            <p><strong>Good habit:</strong> If a message contains a link, hover over it first to preview the real destination.</p>
            <ChevronDown size={17} className="tip-arrow" />
          </section>
        )}
      </main>
      <footer className="site-footer"><span>PhishGuard</span><span>For awareness and education · Always verify through official channels</span></footer>
    </div>
  );
}

export default App;
