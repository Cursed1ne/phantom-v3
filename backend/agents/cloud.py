"""PHANTOM AI v3 — Cloud Agent: AWS/GCP/Azure posture, Kubernetes, S3, IAM."""
from typing import List
from .base import BaseAgent


class CloudAgent(BaseAgent):

    @property
    def agent_id(self): return "cloud"

    @property
    def tools(self):
        return ["scout", "prowler", "kube-hunter", "pacu", "curl"]

    @property
    def persona(self):
        return (
            "You are the PHANTOM CLOUD agent — a cloud security posture management specialist. "
            "You understand the unique attack surface of cloud-native infrastructure. "
            "Your priorities: "
            "1) S3/GCS/Blob — public bucket enumeration, object listing, unauthenticated writes. "
            "2) IAM — overpermissioned roles, privilege escalation paths, unused access keys, "
            "   root account without MFA, cross-account trust policies. "
            "3) Security groups / NACLs — unrestricted ingress (0.0.0.0/0) on sensitive ports. "
            "4) Logging — CloudTrail disabled, GuardDuty off, no VPC flow logs. "
            "5) Secrets — credentials in EC2 metadata service, Lambda env vars, SSM Parameter Store. "
            "6) Kubernetes — exposed API server, privileged containers, RBAC misconfigs, "
            "   service account token leakage. "
            "Format: THOUGHT: ... | HYPOTHESIS: ... | ACTION: <tool_name> | REASON: ..."
        )

    def build_args(self, tool: str, target: str, depth: str) -> List[str]:
        return {
            "scout":       ["aws", "--report-name", "scout-out", "--no-browser"],
            "prowler":     ["aws", "--output-formats", "json", "-q",
                            "--compliance", "cis_level1_aws"],
            "kube-hunter": ["--remote", target, "--report", "json"],
            "pacu":        ["--session", "phantom-session", "--module",
                            "iam__privesc_scan", "--data", "IAM"],
            "curl":        ["http://169.254.169.254/latest/meta-data/", "--max-time", "5"],
        }.get(tool, [target])
