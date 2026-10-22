# scam-signal-engine

**Explainable, deterministic, offline scam-signal scoring** for messages and call transcripts. Built for family-safety voice agents, chatbots, community hotlines and anyone who needs to answer *"is this a scam?"* without an LLM, an API key, or a black box.

Created for the Amazon Developer Hackathon 2026 as the open-source companion to **SafeWord Sentinel** (an Alexa+ MCP server for family AI-scam defence), and released standalone so any builder can use it anywhere.

## Why

AI voice cloning made imposter scams ("Grandma, I've been arrested, send bail money, don't tell anyone") dramatically more convincing. The FTC and FBI publish the red flags — this package turns that public guidance into code:

- **8 named signals**, each with a weight and a plain-language explanation: urgency, secrecy, hard-to-reverse payment methods, family-emergency impersonation, credential requests, threats, isolation tactics, authority impersonation.
- **Deterministic**: same input, same score, every time. Scores are auditable — every point can be traced to a signal a human can read.
- **Offline & zero-dependency at runtime**: safe for on-device, hotline and low-resource contexts. No text ever leaves the machine.
- **Honest by design**: it reports *signals in the text*, not a verdict about a real person. The recommended actions always end with human verification (hang up, call back on a known number, use a family safe word).

## Install

```bash
npm install scam-signal-engine   # or copy src/index.ts — it's one file, zero deps
```

## Use

```ts
import { analyzeScamText } from "scam-signal-engine";

const result = analyzeScamText(
  "It's me, your grandson! I've been arrested, send bail money by gift cards right now and don't tell anyone!"
);

console.log(result.score);   // 95
console.log(result.level);   // "critical"  (low | guarded | high | critical)
console.log(result.matchedSignals.map(s => s.label));
console.log(result.recommendedActions); // FTC/FBI-aligned next steps
console.log(result.verdict);
```

## API

- `analyzeScamText(text: string): ScamAnalysis` — `{ score (0–100), level, matchedSignals[], recommendedActions[], verdict }`
- `levelForScore(score: number): RiskLevel`
- `listSignalIds(): string[]`

## Sources

Signal definitions summarise public consumer guidance from the [FTC](https://consumer.ftc.gov/articles/how-avoid-scam) and the [FBI IC3](https://www.ic3.gov/Media/Y2023/PSA230406) on imposter and AI voice-clone scams. This library is a screening aid, not a guarantee: always verify through a channel you trust.

## Develop

```bash
npm install
npm test        # vitest suite
npm run build   # tsc -> dist/
```

## License

MIT © 2026 Mir Quadri
