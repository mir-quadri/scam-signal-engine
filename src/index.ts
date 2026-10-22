/**
 * Scam-signal rule engine for SafeWord Sentinel.
 *
 * Deterministic, offline, and explainable: every point in the score maps to a
 * named signal with a plain-language explanation. The patterns are grounded in
 * public FTC and FBI guidance on imposter and AI voice-clone scams:
 *  - FTC: scammers impersonate people you know, create urgency, demand secrecy
 *    and insist on specific (hard-to-reverse) payment methods.
 *    https://consumer.ftc.gov/articles/how-avoid-scam
 *  - FBI IC3: criminals use AI-generated voice cloning in "family emergency"
 *    and virtual-kidnapping schemes; the FBI recommends a family code word.
 *    https://www.ic3.gov/Media/Y2023/PSA230406
 */

export interface ScamSignal {
  id: string;
  label: string;
  weight: number;
  explanation: string;
}

export type RiskLevel = "low" | "guarded" | "high" | "critical";

export interface ScamAnalysis {
  score: number; // 0-100
  level: RiskLevel;
  matchedSignals: ScamSignal[];
  recommendedActions: string[];
  verdict: string;
}

interface SignalRule extends ScamSignal {
  patterns: RegExp[];
}

const RULES: SignalRule[] = [
  {
    id: "urgency",
    label: "Artificial urgency",
    weight: 15,
    explanation:
      "The message pressures you to act immediately. Scammers use urgency to stop you from verifying.",
    patterns: [
      /\bright now\b/i,
      /\bimmediately\b/i,
      /\burgent(ly)?\b/i,
      /\bhurry\b/i,
      /\bno time\b/i,
      /\bwithin (the )?(next )?\d+ (minutes?|hours?)\b/i,
      /\bbefore it's too late\b/i,
    ],
  },
  {
    id: "secrecy",
    label: "Demand for secrecy",
    weight: 20,
    explanation:
      "You are told not to tell anyone. Isolation is a hallmark of imposter scams — a real loved one does not need secrecy from the rest of the family.",
    patterns: [
      /\bdon'?t tell\b/i,
      /\bkeep (this|it) (a )?secret\b/i,
      /\bbetween us\b/i,
      /\bno one (can|must) know\b/i,
      /\bdon'?t (call|contact|tell) (mom|dad|your|anyone)\b/i,
    ],
  },
  {
    id: "risky_payment",
    label: "Hard-to-reverse payment method",
    weight: 25,
    explanation:
      "Gift cards, wire transfers, crypto and payment apps are requested because the money is almost impossible to recover. The FTC is explicit: anyone who demands payment this way is a scammer.",
    patterns: [
      /\bgift cards?\b/i,
      /\bwire (transfer|money|the money)\b/i,
      /\bwestern union\b/i,
      /\bmoneygram\b/i,
      /\b(bitcoin|crypto|btc)\b/i,
      /\bcash ?app\b/i,
      /\bzelle\b/i,
      /\bvenmo\b/i,
      /\bprepaid (card|debit)\b/i,
      /\bsend (me )?(money|cash|\$)/i,
    ],
  },
  {
    id: "family_emergency",
    label: "Family-emergency impersonation claim",
    weight: 20,
    explanation:
      "A caller claiming to be a relative in an emergency (arrest, accident, kidnapping, hospital) is the core script of AI voice-clone scams reported by the FBI.",
    patterns: [
      /\b(arrested|in jail|jailed)\b/i,
      /\bkidnapped?\b/i,
      /\baccident\b/i,
      /\bhospital\b/i,
      /\bbail\b/i,
      /\bthis is (your )?(son|daughter|grandson|granddaughter|grandma|grandpa|mom|dad)\b/i,
      /\bi'?m in trouble\b/i,
      /\bneed (money|help) (now|urgently)?\b/i,
    ],
  },
  {
    id: "credential_request",
    label: "Request for codes, passwords or account access",
    weight: 25,
    explanation:
      "No legitimate person or company asks for one-time codes, passwords or PINs on a call. Sharing one hands over the account.",
    patterns: [
      /\b(verification|security|one[- ]time) code\b/i,
      /\byour password\b/i,
      /\bpin (number)?\b/i,
      /\bsocial security\b/i,
      /\bbank (account|login|details)\b/i,
      /\bread (me )?the code\b/i,
      /\bcode (we|i) (just )?sent\b/i,
    ],
  },
  {
    id: "threat",
    label: "Threats or intimidation",
    weight: 20,
    explanation:
      "Threats of arrest, deportation, lawsuits or harm are used to panic victims. Government agencies do not threaten people into instant payment.",
    patterns: [
      /\barrest(ed)? (you|warrant)\b/i,
      /\bdeport/i,
      /\blawsuit\b/i,
      /\bwe will (come|arrest|hurt|kill)\b/i,
      /\byou'?ll (be sorry|regret)\b/i,
      /\bpolice are (coming|on their way)\b/i,
    ],
  },
  {
    id: "isolation",
    label: "Keeping you on the phone / blocking verification",
    weight: 15,
    explanation:
      "Being told to stay on the line prevents the one move that defeats this scam: hanging up and calling the real person on a number you already have.",
    patterns: [
      /\bstay on the (phone|line)\b/i,
      /\bdon'?t hang up\b/i,
      /\bkeep talking\b/i,
      /\bdo not (call|contact) (anyone|them|her|him)\b/i,
    ],
  },
  {
    id: "authority_impersonation",
    label: "Authority impersonation",
    weight: 15,
    explanation:
      "Claims to be the IRS, a bank's fraud department, police or tech support are the most-reported imposter categories at the FTC.",
    patterns: [
      /\bthis is the (irs|fbi|police|sheriff|bank|fraud department)\b/i,
      /\b(irs|fraud department|tech support|microsoft support|amazon support) (calling|here)\b/i,
      /\bofficer \w+\b/i,
      /\bbadge number\b/i,
    ],
  },
];

const BASE_ACTIONS = [
  "Stop. Do not send money, gift cards, or codes while this is unverified.",
  "Hang up, then call the real person back on a number you already have saved — never the number that just called you.",
  "Ask for your family safe word. A caller who cannot say it has not verified who they are.",
];

const CRITICAL_ACTIONS = [
  "Treat this as a likely scam in progress: end the call now and verify through a second channel.",
  "If money was already sent, call your bank immediately and ask them to stop or recall the payment.",
  "Report it in the US to the FBI at ic3.gov and the FTC at ReportFraud.ftc.gov, and warn other family members — scammers reuse the same story.",
];

export function levelForScore(score: number): RiskLevel {
  if (score >= 70) return "critical";
  if (score >= 45) return "high";
  if (score >= 20) return "guarded";
  return "low";
}

export function analyzeScamText(text: string): ScamAnalysis {
  const matched: ScamSignal[] = [];
  let raw = 0;
  for (const rule of RULES) {
    if (rule.patterns.some((p) => p.test(text))) {
      matched.push({
        id: rule.id,
        label: rule.label,
        weight: rule.weight,
        explanation: rule.explanation,
      });
      raw += rule.weight;
    }
  }
  const score = Math.min(100, raw);
  const level = levelForScore(score);

  const verdict =
    level === "critical"
      ? "This matches the known pattern of an AI voice-clone / imposter scam very closely. Do not pay — verify first."
      : level === "high"
        ? "Several strong scam signals are present. Pause and verify through a channel you trust before doing anything."
        : level === "guarded"
          ? "Some scam signals are present. Verify the caller's identity with your family safe word and a callback before acting."
          : "No strong scam signals were found in this text. Stay alert anyway — a familiar voice is no longer proof of identity.";

  return {
    score,
    level,
    matchedSignals: matched,
    recommendedActions:
      level === "critical" || level === "high"
        ? [...BASE_ACTIONS, ...CRITICAL_ACTIONS]
        : BASE_ACTIONS,
    verdict,
  };
}

/** Used by the standalone open-source package and the tests. */
export function listSignalIds(): string[] {
  return RULES.map((r) => r.id);
}
