import { severityMap } from './vuln';

/**
 * Shape of `snyk rift test --experimental --json` output.
 *
 * Rift emits a single top-level `findings` array. Unlike `snyk test` or
 * `snyk code test` there are no stable identifiers, no fingerprints and no
 * project metadata, so reports cannot be deduped or diffed run to run.
 */
export interface RiftLocation {
  file_path: string;
  from_line?: number;
  to_line?: number;
}

export interface RiftFinding {
  title: string;
  severity: string;
  description?: string;
  locations?: RiftLocation[];
  fix_plan?: string;
}

export interface RiftResults {
  findings: RiftFinding[];
}

const SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;

export type RiftSeverity = (typeof SEVERITIES)[number];

function isRiftSeverity(value: unknown): value is RiftSeverity {
  return (
    typeof value === 'string' &&
    (SEVERITIES as readonly string[]).includes(value)
  );
}

/**
 * Detects `snyk rift test --experimental --json` output.
 *
 * Rift is the only Snyk JSON format with a top-level `findings` array, but we
 * validate the member shape too so unrelated payloads that happen to use that
 * key are not misrouted into the Rift template.
 */
export function isRiftData(data: any): boolean {
  if (!data || Array.isArray(data) || !Array.isArray(data.findings)) {
    return false;
  }

  // A clean scan returns `{"findings": []}`. Accept it only when no other
  // known Snyk result key is present.
  if (data.findings.length === 0) {
    return (
      !data.vulnerabilities &&
      !data.infrastructureAsCodeIssues &&
      !data.runs &&
      !data.docker
    );
  }

  return data.findings.every(
    (finding: any) =>
      finding &&
      typeof finding.title === 'string' &&
      isRiftSeverity(finding.severity) &&
      (finding.locations === undefined || Array.isArray(finding.locations)),
  );
}

/**
 * Renders a location's line range. Rift omits `to_line` for single-line
 * findings and omits both for whole-file findings.
 */
export function formatLineRange(location: RiftLocation): string {
  const { from_line: from, to_line: to } = location;

  if (typeof from !== 'number') {
    return '';
  }
  if (typeof to !== 'number' || to === from) {
    return `${from}`;
  }
  return `${from}–${to}`;
}

/**
 * Rift reports paths relative to the scanned root, usually with a leading
 * slash. Strip it so paths read as repository-relative.
 */
export function normalizeFilePath(filePath: string): string {
  return (filePath || '').replace(/^\/+/, '');
}

export interface ProcessedRiftFinding {
  num: number;
  title: string;
  severity: string;
  severityValue: number;
  description: string;
  locations: Array<{ filePath: string; lineRange: string }>;
  fixPlan: string;
  hasFixPlan: boolean;
  searchText: string;
}

export interface ProcessedRiftData {
  findings: ProcessedRiftFinding[];
  totalIssues: number;
  severityCounts: Array<{ severity: string; findingCount: number }>;
  attackSurface: Array<{
    filePath: string;
    findingCount: number;
    barWidth: number;
  }>;
  findingsWithoutFixPlan: string;
  findingsWithoutFixPlanCount: number;
  hasFindings: boolean;
}

/**
 * Normalizes Rift findings for the Handlebars template: orders by severity,
 * tallies counts, and builds the per-file attack-surface table.
 *
 * Rift's own ordering is preserved as the finding number so a report can be
 * read alongside the raw JSON; the display order is severity-first.
 */
export function processRiftFindings(data: RiftResults): ProcessedRiftData {
  const findings = Array.isArray(data.findings) ? data.findings : [];

  const numbered: ProcessedRiftFinding[] = findings.map((finding, index) => {
    const locations = (finding.locations || []).map((location) => ({
      filePath: normalizeFilePath(location.file_path),
      lineRange: formatLineRange(location),
    }));
    const fixPlan = (finding.fix_plan || '').trim();
    const description = finding.description || 'No description available.';

    return {
      num: index + 1,
      title: finding.title,
      severity: finding.severity,
      severityValue: severityMap[finding.severity] ?? -1,
      description,
      locations,
      fixPlan,
      hasFixPlan: fixPlan.length > 0,
      searchText: [
        finding.title,
        description,
        finding.severity,
        ...locations.map((location) => location.filePath),
      ]
        .join(' ')
        .toLowerCase(),
    };
  });

  // Severity descending, then Rift's original order within a severity.
  const ordered = [...numbered].sort(
    (a, b) => b.severityValue - a.severityValue || a.num - b.num,
  );

  // `count` is a registered Handlebars helper, so these must not be named
  // `count` or the template resolves the helper instead of the value.
  const severityCounts = SEVERITIES.map((severity) => ({
    severity,
    findingCount: findings.filter((finding) => finding.severity === severity)
      .length,
  }));

  const fileHits = new Map<string, number>();
  for (const finding of numbered) {
    for (const location of finding.locations) {
      if (!location.filePath) {
        continue;
      }
      fileHits.set(
        location.filePath,
        (fileHits.get(location.filePath) || 0) + 1,
      );
    }
  }
  const maxHits = Math.max(1, ...fileHits.values());
  const attackSurface = [...fileHits.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .slice(0, 10)
    .map(([filePath, fileCount]) => ({
      filePath,
      findingCount: fileCount,
      barWidth: Math.round((100 * fileCount) / maxHits),
    }));

  const withoutFixPlan = ordered.filter((finding) => !finding.hasFixPlan);

  return {
    findings: ordered,
    totalIssues: findings.length,
    severityCounts,
    attackSurface,
    findingsWithoutFixPlan: withoutFixPlan
      .map((finding) => finding.num)
      .sort((a, b) => a - b)
      .map((num) => `#${String(num).padStart(2, '0')}`)
      .join(', '),
    findingsWithoutFixPlanCount: withoutFixPlan.length,
    hasFindings: findings.length > 0,
  };
}
