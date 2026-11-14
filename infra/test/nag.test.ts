import { App, Validations } from 'aws-cdk-lib';
import * as iam from 'aws-cdk-lib/aws-iam';
import { AwsSolutionsChecks } from 'cdk-nag';
import type { IConstruct } from 'constructs';
import { describe, expect, it } from 'vitest';
import { AuthServiceStack } from '../lib/auth-service-stack.js';
import { CDK_CONTEXT, validConfig } from './helpers.js';

function build(overrides: Record<string, unknown> = {}): { app: App; stack: AuthServiceStack } {
  const app = new App({ context: CDK_CONTEXT });
  const stack = new AuthServiceStack(app, 'NagAuthStack', { config: validConfig(overrides) });
  return { app, stack };
}

function acknowledgments(root: IConstruct): { path: string; id: string; reason: string }[] {
  return root.node.findAll().flatMap((c) =>
    c.node.metadata
      .filter((m) => m.type === Validations.ACKNOWLEDGED_RULES_METADATA_KEY)
      .flatMap((m) =>
        Object.entries(m.data as Record<string, string>).map(([id, reason]) => ({
          path: c.node.path,
          id: id.replace(/^annotation::/i, ''),
          reason,
        })),
      ),
  );
}

describe('cdk-nag AwsSolutionsChecks', () => {
  it('reports no unacknowledged findings (errors or warnings)', () => {
    const { app } = build();
    const report = new AwsSolutionsChecks(undefined, { verbose: true }).validateScope(app);
    expect(report.violations.map((v) => `${v.ruleName}: ${JSON.stringify(v.violatingResources)}`)).toEqual([]);
    expect(report.success).toBe(true);
  });

  it('reports no findings when the API Gateway account role is not managed', () => {
    const { app } = build({ manageApiGatewayCloudWatchRole: false });
    expect(new AwsSolutionsChecks().validateScope(app).violations).toEqual([]);
  });

  it('synthesizes with the plugin registered, as bin/app.ts does', () => {
    const { app } = build();
    Validations.of(app).addPlugins(new AwsSolutionsChecks(app));
    expect(() => app.synth()).not.toThrow();
  });

  it('acknowledges only the reviewed findings, each with a specific reason', () => {
    const { app } = build();
    const acks = acknowledgments(app);
    expect(acks.map((a) => `${a.path.replace(/^NagAuthStack\//, '')} ${a.id}`).sort()).toEqual(
      [
        'Api/CloudWatchRole AwsSolutions-IAM4[Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs]',
        'Api/Default/ANY AwsSolutions-APIG4',
        'Api/Default/ANY AwsSolutions-COG4',
        'Api/Default/{proxy+}/ANY AwsSolutions-APIG4',
        'Api/Default/{proxy+}/ANY AwsSolutions-COG4',
        'Api/DeploymentStage.prod AwsSolutions-APIG6',
        'Api/Resource AwsSolutions-APIG2',
      ].sort(),
    );
    for (const a of acks) expect(a.reason.length).toBeGreaterThan(120);
  });

  it('is live: a wildcard IAM policy added to the stack is reported and fails synthesis', () => {
    const { app, stack } = build();
    stack.serviceRole.addToPrincipalPolicy(new iam.PolicyStatement({ actions: ['s3:*'], resources: ['*'] }));
    const report = new AwsSolutionsChecks().validateScope(app);
    expect(report.success).toBe(false);
    expect(report.violations.map((v) => v.ruleName)).toEqual(
      expect.arrayContaining(['AwsSolutions-IAM5[Action::s3:*]', 'AwsSolutions-IAM5[Resource::*]']),
    );
    Validations.of(app).addPlugins(new AwsSolutionsChecks(app));
    expect(() => app.synth()).toThrow();
  });
});
