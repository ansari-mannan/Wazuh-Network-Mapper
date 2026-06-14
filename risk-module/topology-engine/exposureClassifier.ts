/**
 * Classifies exposure (internet-facing, internal, etc.).
 */

export type ExposureClass = "internet-facing" | "internal" | "restricted";

export function classifyExposure(exposure: string): ExposureClass {
  const lower = exposure.toLowerCase();
  if (lower.includes("internet") || lower.includes("facing")) return "internet-facing";
  if (lower.includes("restricted")) return "restricted";
  return "internal";
}
