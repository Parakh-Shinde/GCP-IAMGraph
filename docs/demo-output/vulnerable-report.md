# GCP IAMGraph Security Report

- Resources analyzed: 5
- Findings: 8

## [CRITICAL] Broad primitive role: roles/owner

**Rule:** `GCP-IAM-001`  
**Principal:** `serviceAccount:deployment@payments-prod.iam.gserviceaccount.com`  
**Resource:** `projects/payments-prod`  
**Attack path:** serviceAccount:deployment@payments-prod.iam.gserviceaccount.com → roles/owner → projects/payments-prod → Broad resource control

A principal has a broad primitive role that exceeds typical least-privilege requirements.

**Evidence**
- serviceAccount:deployment@payments-prod.iam.gserviceaccount.com has roles/owner on projects/payments-prod

**Remediation:** Replace primitive roles with predefined or custom roles containing only required permissions.

## [CRITICAL] Public or globally authenticated access

**Rule:** `GCP-IAM-002`  
**Principal:** `allUsers`  
**Resource:** `projects/payments-prod`  
**Attack path:** allUsers → roles/storage.objectViewer → projects/payments-prod

The IAM binding grants access to a public principal.

**Evidence**
- allUsers has roles/storage.objectViewer on projects/payments-prod

**Remediation:** Remove the public member and grant the minimum role to explicitly identified principals.

## [CRITICAL] IAM policy modification

**Rule:** `GCP-IAM-003`  
**Principal:** `user:iam-operator@example.test`  
**Resource:** `projects/payments-prod`  
**Attack path:** user:iam-operator@example.test → resourcemanager.projects.setIamPolicy → projects/payments-prod → Privilege expansion

A principal can change project IAM bindings and grant additional access.

**Evidence**
- user:iam-operator@example.test has roles/resourcemanager.projectIamAdmin on projects/payments-prod

**Remediation:** Restrict this permission to a controlled deployment identity and require short-lived credentials and approval controls.

## [CRITICAL] Service-account impersonation reaches a privileged role

**Rule:** `GCP-IAM-005`  
**Principal:** `user:developer@example.test`  
**Resource:** `projects/payments-prod`  
**Attack path:** user:developer@example.test → impersonates → serviceAccount:deployment@payments-prod.iam.gserviceaccount.com → roles/owner → projects/payments-prod

The principal can obtain short-lived credentials for a service account with broad access.

**Evidence**
- user:developer@example.test has roles/iam.serviceAccountTokenCreator on projects/payments-prod/serviceAccounts/deployment@payments-prod.iam.gserviceaccount.com
- serviceAccount:deployment@payments-prod.iam.gserviceaccount.com has roles/owner on projects/payments-prod

**Remediation:** Remove unnecessary Token Creator bindings and grant impersonation only on narrowly scoped service accounts.

## [CRITICAL] IAM policy modification can escalate to project Owner

**Rule:** `GCP-IAM-007`  
**Principal:** `user:iam-operator@example.test`  
**Resource:** `projects/payments-prod`  
**Attack path:** user:iam-operator@example.test → resourcemanager.projects.setIamPolicy → projects/payments-prod → grant roles/owner → Project compromise

The principal can modify the project IAM policy and grant itself or another controlled identity the Owner role.

**Evidence**
- user:iam-operator@example.test has roles/resourcemanager.projectIamAdmin on projects/payments-prod

**Remediation:** Restrict project IAM policy modification to a controlled administrative identity. Require approval, audit IAM changes, and prevent direct Owner grants.

## [CRITICAL] Key creation reaches a privileged service account

**Rule:** `GCP-IAM-008`  
**Principal:** `user:contractor@example.test`  
**Resource:** `projects/payments-prod`  
**Attack path:** user:contractor@example.test → iam.serviceAccountKeys.create → serviceAccount:deployment@payments-prod.iam.gserviceaccount.com → create long-lived credential → roles/owner → projects/payments-prod → Project compromise

The principal can create a long-lived key for a service account that has a broad primitive role.

**Evidence**
- user:contractor@example.test has roles/iam.serviceAccountKeyAdmin on projects/payments-prod/serviceAccounts/deployment@payments-prod.iam.gserviceaccount.com inherited from projects/payments-prod
- serviceAccount:deployment@payments-prod.iam.gserviceaccount.com has roles/owner on projects/payments-prod

**Remediation:** Remove unnecessary service-account key creation access. Use short-lived credentials, workload identity federation, and organization policies that disable service-account key creation.

## [HIGH] Broad primitive role: roles/editor

**Rule:** `GCP-IAM-001`  
**Principal:** `group:developers@example.test`  
**Resource:** `folders/engineering`  
**Attack path:** group:developers@example.test → roles/editor → folders/engineering → Broad resource control

A principal has a broad primitive role that exceeds typical least-privilege requirements.

**Evidence**
- group:developers@example.test has roles/editor on folders/engineering

**Remediation:** Replace primitive roles with predefined or custom roles containing only required permissions.

## [HIGH] Service-account key creation

**Rule:** `GCP-IAM-004`  
**Principal:** `user:contractor@example.test`  
**Resource:** `projects/payments-prod`  
**Attack path:** user:contractor@example.test → iam.serviceAccountKeys.create → projects/payments-prod → Privilege expansion

A principal can create long-lived credentials for a service account.

**Evidence**
- user:contractor@example.test has roles/iam.serviceAccountKeyAdmin on projects/payments-prod

**Remediation:** Restrict this permission to a controlled deployment identity and require short-lived credentials and approval controls.

