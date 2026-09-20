/**
 * Mirrors the Pydantic schemas in backend/src/netsentinel_api/schemas.py.
 *
 * Hand-written rather than generated, because the generated client would be another
 * build step for eight types. If the API changes, this file changes with it - and the
 * one field that must never appear here is a password of any kind.
 */

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export type AlertStatus =
  | 'new'
  | 'triaging'
  | 'escalated'
  | 'closed_true_positive'
  | 'closed_false_positive'

export type ActionStatus =
  | 'pending_approval'
  | 'approved'
  | 'rejected'
  | 'executed'
  | 'rolled_back'
  | 'failed'

export type ActionType = 'block_ip' | 'isolate_host' | 'kill_process' | 'disable_account'

export type ApprovalDecision = 'approved' | 'rejected'

export interface TokenResponse {
  access_token: string
  token_type: string
  expires_in: number
}

export interface User {
  user_id: number
  username: string
  email: string
  is_active: boolean
}

/** GET /auth/me - identity plus what this account may do. */
export interface CurrentUser extends User {
  role: string | null
  permissions: string[]
}

export interface Alert {
  alert_id: number
  source: string
  severity: Severity
  status: AlertStatus
  src_ip: string | null
  dst_ip: string | null
  mitre_technique: string | null
  created_at: string
  detection_id: number | null
}

export interface Explanation {
  risk_score: number
  model_scores: Record<string, number>
  feature_contributions: Record<string, number>
  /** Feature names ordered by absolute contribution, strongest first. */
  top_features: string[]
  /** True when the verdict was logged but not acted on. */
  shadow: boolean
}

export interface AlertDetail extends Alert {
  /**
   * Absent when the alert came from Suricata or Wazuh rather than a model. That is
   * not the same as a model having found nothing, and the UI must not conflate them.
   */
  explanation: Explanation | null
  ioc_values: string[]
}

export interface Approval {
  approval_id: number | null
  approver_id: number
  decision: ApprovalDecision
  comment: string | null
  decided_at: string | null
}

export interface ResponseAction {
  action_id: number
  alert_id: number
  action_type: ActionType
  target: string
  status: ActionStatus
  executed_at: string | null
  approval: Approval | null
}

export interface Health {
  status: string
  version: string
  /** Size of the model input vector the API was built against. */
  feature_dim: number
}

/** Permission strings from backend/src/netsentinel_api/rbac.py. */
export const PERMISSIONS = {
  alertsRead: 'alerts:read',
  alertsTriage: 'alerts:triage',
  approvalsDecide: 'approvals:decide',
  modelsDeploy: 'models:deploy',
} as const
