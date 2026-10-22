import { describe, it, expect } from "vitest";
import { analyzeScamText, levelForScore, listSignalIds } from "../src/index.js";

describe("scam-signal-engine", () => {
  it("scores a voice-clone family-emergency script as critical", () => {
    const r = analyzeScamText("Grandma, it's me, your grandson! I've been arrested and I need bail money right now. Don't tell Mom and Dad. Stay on the phone and send money by gift cards, hurry!");
    expect(r.level).toBe("critical");
    expect(r.score).toBeGreaterThanOrEqual(70);
  });
  it("scores a benign family message as low", () => {
    expect(analyzeScamText("Dinner Sunday at 6, bring dessert!").level).toBe("low");
  });
  it("exposes 8 signals and monotonic levels", () => {
    expect(listSignalIds().length).toBe(8);
    expect(levelForScore(90)).toBe("critical");
    expect(levelForScore(0)).toBe("low");
  });
});
