import { describe, expect, it } from '@jest/globals';

import * as path from 'node:path';
import { SnykToHtml } from '../src/lib/snyk-to-html';
import {
  formatLineRange,
  isRiftData,
  normalizeFilePath,
  processRiftFindings,
} from '../src/lib/riftutil';

const WITHOUT_SUMMARY = false;
const WITH_SUMMARY = true;
const WITHOUT_REMEDIATION = false;

const DEFAULT_TEMPLATE = path.join(
  __dirname,
  '..',
  'template',
  'test-report.hbs',
);
const RIFT_FIXTURE = path.join(__dirname, 'fixtures', 'rift-test-report.json');
const RIFT_EMPTY_FIXTURE = path.join(
  __dirname,
  'fixtures',
  'rift-test-report-no-findings.json',
);

describe('isRiftData', () => {
  it('detects rift test output', () => {
    expect(
      isRiftData({
        findings: [
          {
            title: 'A finding',
            severity: 'high',
            description: 'why',
            locations: [{ file_path: 'src/a.ts', from_line: 1, to_line: 2 }],
            fix_plan: '',
          },
        ],
      }),
    ).toBe(true);
  });

  it('detects a clean rift scan', () => {
    expect(isRiftData({ findings: [] })).toBe(true);
  });

  it('rejects other snyk result formats', () => {
    expect(isRiftData({ vulnerabilities: [] })).toBe(false);
    expect(isRiftData({ infrastructureAsCodeIssues: [] })).toBe(false);
    expect(isRiftData({ runs: [] })).toBe(false);
    expect(isRiftData({ docker: {} })).toBe(false);
    expect(isRiftData([{ vulnerabilities: [] }])).toBe(false);
    expect(isRiftData(undefined)).toBe(false);
  });

  it('rejects a findings array that is not rift shaped', () => {
    expect(isRiftData({ findings: [{ id: 'SNYK-1' }] })).toBe(false);
    expect(
      isRiftData({ findings: [{ title: 'x', severity: 'unknown-level' }] }),
    ).toBe(false);
  });

  it('does not claim an empty findings array alongside other snyk keys', () => {
    expect(isRiftData({ findings: [], vulnerabilities: [] })).toBe(false);
  });
});

describe('formatLineRange', () => {
  it('renders a span', () => {
    expect(formatLineRange({ file_path: 'a', from_line: 3, to_line: 9 })).toBe(
      '3–9',
    );
  });

  it('renders a single line when to_line is missing or equal', () => {
    expect(formatLineRange({ file_path: 'a', from_line: 3 })).toBe('3');
    expect(formatLineRange({ file_path: 'a', from_line: 3, to_line: 3 })).toBe(
      '3',
    );
  });

  it('renders nothing for a whole-file location', () => {
    expect(formatLineRange({ file_path: 'a' })).toBe('');
  });
});

describe('normalizeFilePath', () => {
  it('strips the leading slash rift adds to repository-relative paths', () => {
    expect(normalizeFilePath('/Dockerfile')).toBe('Dockerfile');
    expect(normalizeFilePath('src/lib/a.ts')).toBe('src/lib/a.ts');
  });
});

describe('processRiftFindings', () => {
  const data = {
    findings: [
      { title: 'low one', severity: 'low', locations: [], fix_plan: 'fix it' },
      {
        title: 'critical one',
        severity: 'critical',
        description: 'bad',
        locations: [
          { file_path: '/src/a.ts', from_line: 1, to_line: 4 },
          { file_path: '/src/b.ts', from_line: 7 },
        ],
        fix_plan: '',
      },
      {
        title: 'high one',
        severity: 'high',
        locations: [{ file_path: '/src/a.ts', from_line: 20 }],
        fix_plan: '   ',
      },
    ],
  };

  it('orders findings by severity while keeping rift numbering', () => {
    const { findings } = processRiftFindings(data);
    expect(findings.map((f) => f.severity)).toEqual([
      'critical',
      'high',
      'low',
    ]);
    // Rift's own position in the JSON is preserved as the finding number.
    expect(findings.map((f) => f.num)).toEqual([2, 3, 1]);
  });

  it('tallies every severity, including ones with no findings', () => {
    expect(processRiftFindings(data).severityCounts).toEqual([
      { severity: 'critical', findingCount: 1 },
      { severity: 'high', findingCount: 1 },
      { severity: 'medium', findingCount: 0 },
      { severity: 'low', findingCount: 1 },
    ]);
  });

  it('treats a whitespace-only fix plan as absent', () => {
    const { findings, findingsWithoutFixPlan, findingsWithoutFixPlanCount } =
      processRiftFindings(data);
    expect(findings.map((f) => f.hasFixPlan)).toEqual([false, false, true]);
    expect(findingsWithoutFixPlanCount).toBe(2);
    expect(findingsWithoutFixPlan).toBe('#02, #03');
  });

  it('builds the attack surface from normalized paths', () => {
    expect(processRiftFindings(data).attackSurface).toEqual([
      { filePath: 'src/a.ts', findingCount: 2, barWidth: 100 },
      { filePath: 'src/b.ts', findingCount: 1, barWidth: 50 },
    ]);
  });

  it('falls back to a placeholder description', () => {
    const [, , low] = processRiftFindings(data).findings;
    expect(low.description).toBe('No description available.');
  });

  it('handles a clean scan', () => {
    const processed = processRiftFindings({ findings: [] });
    expect(processed.hasFindings).toBe(false);
    expect(processed.totalIssues).toBe(0);
    expect(processed.attackSurface).toEqual([]);
  });
});

describe('SnykToHtml.run with rift input', () => {
  it('renders a rift report from the default template', (done) => {
    SnykToHtml.run(
      RIFT_FIXTURE,
      WITHOUT_REMEDIATION,
      DEFAULT_TEMPLATE,
      WITHOUT_SUMMARY,
      (report) => {
        try {
          expect(report).toContain(
            '<h1 class="project__header__title">Snyk Rift test report</h1>',
          );
          expect(report).toContain('snyk rift test --experimental --json');
          expect(report).toContain(
            '<span>5</span> <span>total findings</span>',
          );

          // Highest severity first.
          expect(report.indexOf('IDOR on account balance')).toBeGreaterThan(
            report.indexOf('Transfer API lacks ownership check'),
          );

          // Locations, line ranges and the missing-fix-plan state.
          expect(report).toContain(
            '<code>src/com/ibm/security/appscan/altoromutual/api/TransferAPI.java</code>',
          );
          expect(report).toContain(
            '<span class="locations__lines">30–33</span>',
          );
          expect(report).toContain(
            'Rift returned no fix plan for this finding.',
          );

          // Rift paths are reported with a leading slash; strip it.
          expect(report).toContain('<code>Dockerfile.new</code>');
          expect(report).not.toContain('<code>/Dockerfile.new</code>');

          // Severity tiles and the attack surface table.
          // `count` is a Handlebars helper name; assert the rendered value,
          // not just the tile markup.
          expect(report).toMatch(
            /tile tile--critical">\s*<span class="tile__count">1<\/span>/,
          );
          expect(report).toMatch(
            /tile tile--medium">\s*<span class="tile__count">2<\/span>/,
          );
          expect(report).toContain('Attack surface');
          expect(report).toMatch(/<td class="surface__count">\d+<\/td>/);

          // The caveats a rift report has to carry.
          expect(report).toContain('carry no stable identifiers');
          expect(report).toContain('2 of 5 findings carry no fix plan');
          done();
        } catch (error: any) {
          done(error);
        }
      },
    );
  });

  it('escapes finding text rather than trusting the scan JSON', (done) => {
    SnykToHtml.run(
      RIFT_FIXTURE,
      WITHOUT_REMEDIATION,
      DEFAULT_TEMPLATE,
      WITHOUT_SUMMARY,
      (report) => {
        try {
          // The fixture description contains a literal quote; it must arrive
          // escaped, and no finding text may open a tag.
          expect(report).toContain('&quot;');
          expect(report).not.toMatch(/<script>(?![\s\S]{0,40}\(function)/);
          done();
        } catch (error: any) {
          done(error);
        }
      },
    );
  });

  it('omits finding detail in summary mode', (done) => {
    SnykToHtml.run(
      RIFT_FIXTURE,
      WITHOUT_REMEDIATION,
      DEFAULT_TEMPLATE,
      WITH_SUMMARY,
      (report) => {
        try {
          expect(report).toContain(
            '<h1 class="project__header__title">Snyk Rift test summary</h1>',
          );
          expect(report).toMatch(
            /tile tile--critical">\s*<span class="tile__count">1<\/span>/,
          );
          expect(report).not.toContain('class="card card--vuln card--finding');
          expect(report).not.toContain('Attack surface');
          done();
        } catch (error: any) {
          done(error);
        }
      },
    );
  });

  it('renders a clean rift scan', (done) => {
    SnykToHtml.run(
      RIFT_EMPTY_FIXTURE,
      WITHOUT_REMEDIATION,
      DEFAULT_TEMPLATE,
      WITHOUT_SUMMARY,
      (report) => {
        try {
          expect(report).toContain('No findings reported by Rift.');
          expect(report).toContain(
            '<span>0</span> <span>total findings</span>',
          );
          done();
        } catch (error: any) {
          done(error);
        }
      },
    );
  });

  it('honours an explicit -t template over rift detection', (done) => {
    SnykToHtml.run(
      RIFT_FIXTURE,
      WITHOUT_REMEDIATION,
      path.join(__dirname, '..', 'template', 'rift', 'test-report.hbs'),
      WITHOUT_SUMMARY,
      (report) => {
        try {
          expect(report).toContain('Snyk Rift test report');
          done();
        } catch (error: any) {
          done(error);
        }
      },
    );
  });
});
