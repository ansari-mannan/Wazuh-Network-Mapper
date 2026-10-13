// The shared recommendations tracker lives beside the graph, like targets.json
// and attack_paths.json. It records only the items a user has moved off Open.
import path from 'path';
import { RecommendationStatus, RecommendationsFile } from '../common';

export function recommendationsFilePath(graphPath: string): string {
  return path.join(path.dirname(path.resolve(graphPath)), 'recommendations.json');
}

/** Parse the file, tolerating an absent or malformed one as an empty tracker. */
export function readRecommendations(data: string | null): RecommendationsFile {
  if (!data) return { statuses: {} };
  try {
    const doc = JSON.parse(data);
    return doc && typeof doc.statuses === 'object' && !Array.isArray(doc.statuses) ? doc : { statuses: {} };
  } catch {
    return { statuses: {} };
  }
}

/**
 * Upsert one item's status; `open` (the default) deletes the entry so the file
 * only holds items moved off Open. Pure.
 */
export function applyRecommendationStatus(
  file: RecommendationsFile,
  key: string,
  status: RecommendationStatus
): RecommendationsFile {
  const statuses = { ...file.statuses };
  if (status === 'open') delete statuses[key];
  else statuses[key] = { status, updated: new Date().toISOString() };
  return { statuses };
}
