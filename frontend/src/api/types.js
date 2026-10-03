/**
 * The shapes the API sends and accepts, documented as JSDoc typedefs.
 *
 * These are comments, not code - nothing here runs. They exist so the shape of an alert
 * is written down somewhere, and so an editor can offer completions on `alert.severity`.
 * Mirrors backend/src/netsentinel_api/schemas.py; if that changes, this changes with it.
 *
 * The one field that must never appear here is a password of any kind.
 */

/** @typedef {'info' | 'low' | 'medium' | 'high' | 'critical'} Severity */

/**
 * @typedef {'new' | 'triaging' | 'escalated' | 'closed_true_positive'
 *   | 'closed_false_positive'} AlertStatus
 */

/**
 * @typedef {'pending_approval' | 'approved' | 'rejected' | 'executed'
 *   | 'rolled_back' | 'failed'} ActionStatus
 */

/** @typedef {'block_ip' | 'isolate_host' | 'kill_process' | 'disable_account'} ActionType */

/** @typedef {'approved' | 'rejected'} ApprovalDecision */

/**
 * @typedef {object} TokenResponse
 * @property {string} access_token
 * @property {string} token_type
 * @property {number} expires_in seconds until the token expires
 */

/**
 * GET /auth/me - identity plus what this account may do.
 *
 * @typedef {object} CurrentUser
 * @property {number} user_id
 * @property {string} username
 * @property {string} email
 * @property {boolean} is_active
 * @property {string | null} role
 * @property {string[]} permissions
 */

/**
 * A feed row. Deliberately compact - the dashboard renders hundreds.
 *
 * @typedef {object} Alert
 * @property {number} alert_id
 * @property {string} source
 * @property {Severity} severity
 * @property {AlertStatus} status
 * @property {string | null} src_ip
 * @property {string | null} dst_ip
 * @property {string | null} mitre_technique
 * @property {string} created_at
 * @property {number | null} detection_id
 */

/**
 * Why the model said what it said.
 *
 * `feature_contributions` maps a contract feature name to its SHAP value. The keys come
 * from the backend, which takes them from FEATURE_ORDER, so the dashboard never invents
 * a feature name.
 *
 * @typedef {object} Explanation
 * @property {number} risk_score
 * @property {Record<string, number>} model_scores
 * @property {Record<string, number>} feature_contributions
 * @property {string[]} top_features strongest absolute contribution first
 * @property {boolean} shadow true when the verdict was logged but not acted on
 * @property {Record<string, number> | null} features the input values the verdict was
 *   computed from; null for a detection stored before they were recorded
 */

/**
 * `explanation` is null when the alert came from Suricata or Wazuh rather than a model.
 * That is not the same as a model having found nothing, and the UI must not conflate them.
 *
 * @typedef {Alert & {
 *   explanation: Explanation | null,
 *   ioc_values: string[],
 *   corroborated_by_alert_id: number | null,
 * }} AlertDetail
 */

/**
 * @typedef {object} Approval
 * @property {number | null} approval_id
 * @property {number} approver_id
 * @property {ApprovalDecision} decision
 * @property {string | null} comment
 * @property {string | null} decided_at
 */

/**
 * @typedef {object} ResponseAction
 * @property {number} action_id
 * @property {number} alert_id
 * @property {ActionType} action_type
 * @property {string} target
 * @property {ActionStatus} status
 * @property {string | null} executed_at
 * @property {Approval | null} approval
 * @property {boolean} undoable whether a rollback can be asked for at all
 */

/** @typedef {'A' | 'B' | 'C' | 'D'} ModelTier */

/** @typedef {'shadow' | 'active' | 'retired'} ModelMode */

/**
 * What one model did over the report window.
 *
 * Not ground truth, and the UI must not present it as such. These are counts of
 * agreement with analyst verdicts on the flows that were triaged - a biased sample,
 * because nobody labels the traffic nothing fired on. `unlabelled` is rendered beside
 * `precision` for that reason.
 *
 * A null metric means nothing could be computed for it, which is not the same as zero.
 *
 * @typedef {object} ModelEvidence
 * @property {number} scored verdicts recorded in the window
 * @property {number} labelled of those, ones an analyst closed a verdict on
 * @property {number} unlabelled
 * @property {number} true_positives
 * @property {number} false_positives
 * @property {number} false_negatives
 * @property {number | null} precision
 * @property {number | null} recall
 * @property {number | null} f1
 * @property {number | null} average_precision how candidates are compared
 * @property {number | null} false_positives_per_day
 * @property {number} days span of shadow traffic observed in the window
 */

/**
 * A registry row with the evidence for and against promoting it.
 *
 * `blocked_by` is a sentence rather than a boolean, so the page can say what is
 * missing instead of only disabling a button.
 *
 * @typedef {object} MLModel
 * @property {number} model_id
 * @property {string} name
 * @property {ModelTier} tier
 * @property {string} version
 * @property {number} threshold
 * @property {ModelMode} mode
 * @property {number | null} pr_auc from the training run, not from live traffic
 * @property {string | null} deployed_at
 * @property {ModelEvidence} evidence
 * @property {string | null} blocked_by
 */

/**
 * One minute of the activity strip.
 *
 * @typedef {object} ActivityBucket
 * @property {string} start minute-aligned, UTC
 * @property {number} alerts
 * @property {number | null} flows null when flow counts are unavailable, never 0 for that
 */

/**
 * GET /activity - the recent past, a minute at a time. The newest bucket is the
 * current, still-filling minute.
 *
 * @typedef {object} Activity
 * @property {number} minutes
 * @property {string} until end of the newest bucket
 * @property {ActivityBucket[]} buckets oldest first
 * @property {boolean} flows_available
 */

/**
 * A host of the estate, from the inventory import.
 *
 * @typedef {object} Asset
 * @property {number} asset_id
 * @property {string} hostname
 * @property {string} ip_address
 * @property {string | null} os
 * @property {'low' | 'medium' | 'high'} criticality
 * @property {string | null} last_scanned_at when a vulnerability scan last covered it
 */

/**
 * A CVE a Greenbone scan reported on one host.
 *
 * @typedef {object} Vulnerability
 * @property {number} vuln_id
 * @property {string} cve_id
 * @property {number | null} cvss null when the scan gave no score
 * @property {string} detected_at when the scan saw it, ISO 8601
 */

/**
 * GET /admin/roles
 *
 * @typedef {object} Role
 * @property {string} name
 * @property {string[]} permissions
 */

/**
 * An account on the admin page.
 *
 * @typedef {object} Account
 * @property {number} user_id
 * @property {string} username
 * @property {string} email
 * @property {boolean} is_active
 * @property {string | null} role
 * @property {string | null} created_at
 */

/**
 * @typedef {object} Sensor
 * @property {number} sensor_id
 * @property {'suricata' | 'zeek' | 'early_flow' | 'wazuh_agent' | 'openvas'} type
 * @property {string} hostname the inventory host it runs on
 * @property {'online' | 'offline' | 'degraded'} status
 * @property {string | null} last_seen
 * @property {boolean} revoked the writer refuses to ingest for a revoked sensor
 */

/**
 * One audit_log row.
 *
 * @typedef {object} AuditEntry
 * @property {number} log_id
 * @property {string} ts
 * @property {number | null} user_id
 * @property {string | null} username null for a system action
 * @property {string} action
 * @property {string} entity
 * @property {Record<string, unknown>} details
 */

/**
 * @typedef {object} Health
 * @property {string} status
 * @property {string} version
 * @property {number} feature_dim size of the model input vector in use
 */

/**
 * Permission strings from backend/src/netsentinel_api/rbac.py.
 *
 * These are real values rather than documentation: the UI compares against them to
 * decide what to render.
 */
export const PERMISSIONS = {
  alertsRead: 'alerts:read',
  alertsTriage: 'alerts:triage',
  approvalsDecide: 'approvals:decide',
  responsePropose: 'response:propose',
  modelsRead: 'models:read',
  modelsDeploy: 'models:deploy',
  assetsRead: 'assets:read',
  usersManage: 'users:manage',
  sensorsManage: 'sensors:manage',
  auditRead: 'audit:read',
}
