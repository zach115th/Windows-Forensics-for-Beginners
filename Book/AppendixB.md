# Appendix B — Cloud Identity and Microsoft 365 Forensics

This book covers Windows endpoint forensics in depth, but most consequential intrusions in modern enterprises also touch cloud identity, and some start there. An attacker who phishes a user's credentials usually authenticates against Microsoft Entra ID before touching a Windows host. An attacker who exfiltrates data may use Outlook on the web rather than a sync client, which leaves little disk evidence but plenty of cloud audit data. A working IR practitioner needs to read both the host-side and the cloud-side picture.

This appendix introduces the cloud-side artifacts that pair most directly with the host-side material in earlier chapters. The focus is Microsoft 365 / Entra ID, because most enterprise Windows shops run it. Google Workspace and Okta appear for comparison.

## B.1 The Three Tenant-Side Logs You Actually Need

Microsoft exposes a broad telemetry surface, but for incident response three log types carry most of the value:

| Log | What it covers | Where to query it |
|---|---|---|
| **Microsoft Entra ID Sign-in Logs** | Every authentication event, with source IP, user, application, conditional-access result, MFA outcome, risk score | Entra ID portal → Sign-in logs; or `SigninLogs` in Sentinel |
| **Microsoft Entra ID Audit Logs** | Directory changes (group membership, app consent, role assignment, password reset, etc.) | Entra ID portal → Audit logs; or `AuditLogs` in Sentinel |
| **Unified Audit Log (UAL)** | M365 service activity (Exchange, SharePoint, OneDrive, Teams, Power Platform, Purview, Defender for Cloud Apps) | Compliance portal → Audit; or `Search-UnifiedAuditLog` PowerShell; or `OfficeActivity` in Sentinel |

Together, these three logs answer the most common cloud-side IR questions. On most plans, you can retain each of them substantially longer than disk-side telemetry. Sign-in and Audit logs default to 30 days but can be extended. The UAL retains 180 days for E5, with longer windows on add-on licenses.

## B.2 Sign-in Logs: Authentication Forensics

Sign-in logs are the cloud equivalent of `Security.evtx` EID 4624. Each row is one authentication event.

### B.2.1 Fields that matter

| Field | Why it matters |
|---|---|
| `UserPrincipalName` | Who tried to sign in |
| `IPAddress` | Source IP of the auth attempt |
| `Location` (City / State / Country) | Geo-IP of the source |
| `AppDisplayName` / `AppId` | Which application or resource was being accessed (Outlook, Azure portal, custom app, etc.) |
| `AuthenticationDetails` | Auth methods attempted (password, MFA, FIDO2, etc.) and which succeeded |
| `ConditionalAccessStatus` | Was a CA policy applied; if so, what was the result |
| `RiskState` and `RiskLevel` | Entra ID's risk classification (none / low / medium / high) |
| `Status.ErrorCode` | Why the sign-in succeeded or failed |
| `DeviceDetail` | Which device the sign-in came from (if managed / known) |

### B.2.2 KQL queries you will actually run

**All sign-ins from a specific user in a window:**

```kql
SigninLogs
| where TimeGenerated between (datetime(2024-11-12 00:00:00) .. datetime(2024-11-13 00:00:00))
| where UserPrincipalName == "hr-user@finance.example.com"
| project TimeGenerated, IPAddress, Location, AppDisplayName, ResultType, ResultDescription,
          ConditionalAccessStatus, RiskState
| sort by TimeGenerated asc
```

**Impossible-travel detection** (same user, two distant locations within an hour):

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| extend country = tostring(LocationDetails.countryOrRegion)
| summarize locations = make_set(country), times = make_list(TimeGenerated)
            by UserPrincipalName, bin(TimeGenerated, 1h)
| where array_length(locations) > 1
```

**Failed sign-ins followed by a success from the same IP** (password-spray success):

```kql
SigninLogs
| where TimeGenerated > ago(1d)
| summarize fails = countif(ResultType != 0), succs = countif(ResultType == 0),
            success_users = make_set_if(UserPrincipalName, ResultType == 0)
            by IPAddress, bin(TimeGenerated, 1h)
| where fails > 20 and succs >= 1
```

**Sign-ins where MFA was bypassed or skipped:**

```kql
SigninLogs
| where TimeGenerated > ago(7d)
| where AuthenticationRequirement == "singleFactorAuthentication"
| where UserType == "Member"
| project TimeGenerated, UserPrincipalName, IPAddress, AppDisplayName,
          ConditionalAccessStatus, ResultType
```

### B.2.3 Patterns worth alerting on

- New geographic location for a user who normally signs in from a single country
- Sign-ins from anonymizing infrastructure, such as Tor exit nodes and residential proxies. Entra ID's risk engine flags many of these
- Successful sign-ins that bypass conditional access via the legacy authentication protocols (`Other clients`, `IMAP`, `POP3`, `SMTP AUTH`, `Exchange ActiveSync` basic auth)
- Sign-ins to administrative apps (`Microsoft Graph PowerShell`, `Azure Active Directory PowerShell`) from non-administrator accounts
- A burst of failed sign-ins followed by a single success — classic password spray or credential stuffing

## B.3 Audit Logs: Directory Forensics

Audit logs cover changes to the directory itself. The single most common attacker pattern visible here:

**Application consent grants.** An attacker phishes a user, and the user clicks through an OAuth consent prompt. The attacker's application now has persistent access, such as `Mail.Read`, `Files.Read.All`, or `User.Read.All`, without ever needing the user's password again. The grant also bypasses MFA: once consent is granted, the application uses tokens, not credentials.

**KQL: recent application consent grants:**

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Consent to application"
| extend permissions = tostring(parse_json(tostring(TargetResources[0].modifiedProperties[4].newValue)))
| project TimeGenerated, InitiatedBy, AppDisplayName=tostring(TargetResources[0].displayName),
          permissions, IPAddress=tostring(InitiatedBy.user.ipAddress)
```

Other audit events worth knowing:

| OperationName | Meaning |
|---|---|
| `Add member to role` | Privileged role assignment (Global Admin, Privileged Role Admin, etc.) |
| `Add owner to application` / `Add owner to service principal` | Granting app/SP ownership — equivalent to making someone admin of that app's permissions |
| `Update application – Certificates and secrets management` | New credentials added to a service principal; common persistence technique |
| `Add service principal credentials` | Same; from a different angle |
| `Reset user password` | Password reset; check the Initiator field — is it the user themselves, helpdesk, or an unexpected admin? |
| `Update user` (with `StrongAuthenticationMethod` changed) | MFA method changed; an attacker who can change the user's MFA method has effectively bypassed MFA going forward |

A combination of *new application consent* + *new service principal credentials* + *role addition* is a tenant-takeover pattern that should trigger immediate alerting.

## B.4 Unified Audit Log: M365 Service Forensics

The Unified Audit Log (UAL) is the consolidated record of M365 service activity. Each event carries an `Operation` name and a `RecordType`. These records come up most often in IR:

### B.4.1 Exchange Online

| Operation | Meaning | Use |
|---|---|---|
| `MailItemsAccessed` | A mail item was opened or accessed (E5 only) | Confirming what mail an attacker read after compromising an account |
| `Send` / `SendOnBehalf` | Mail sent | Confirming exfiltration via outbound mail or impersonation patterns |
| `New-InboxRule` / `Set-InboxRule` | Inbox rule created or modified | Auto-forward rules to attacker mailboxes are a classic post-compromise persistence |
| `Add-MailboxPermission` / `Add-RecipientPermission` | Permissions granted on a mailbox | Attacker grants themselves Full Access or Send As to a high-value mailbox |
| `UpdateInboxRules` | Inbox rule modification | Same intent as New-InboxRule |
| `Set-Mailbox` (with `ForwardingSmtpAddress`) | Server-side forwarding configured | Same intent — every mail forwarded to an external address |

`MailItemsAccessed` is the highest-value Exchange UAL record. When an account is compromised, it is the only record that answers the question "what did the attacker read?"

### B.4.2 SharePoint and OneDrive

| Operation | Meaning |
|---|---|
| `FileDownloaded` | A file was downloaded from SharePoint or OneDrive |
| `FileSyncDownloadedFull` / `FileSyncUploadedFull` | OneDrive sync activity from a client |
| `FileAccessed` | A file was read or previewed |
| `AnonymousLinkCreated` / `SharingSet` | A sharing link was created — sometimes used to exfiltrate by creating a public link to a file |
| `FileDeleted` | A file was deleted (recoverable from Recycle Bin or version history for some plans) |

A burst of `FileDownloaded` events for sensitive content from an unfamiliar IP is a textbook exfiltration signal.

### B.4.3 Teams and Power Platform

| Operation | Meaning |
|---|---|
| `MessageCreatedHasLink` | Teams message containing a link sent (sometimes phishing within the tenant) |
| `MemberAdded` (channel / team) | Membership change |
| `Power Apps`, `Power Automate` operations | Custom flows are an increasingly common persistence path |

### B.4.4 KQL examples for UAL

In Sentinel, UAL data lives in `OfficeActivity`:

```kql
// Mailbox items accessed by a specific user in the past 24 hours
OfficeActivity
| where TimeGenerated > ago(1d)
| where Operation == "MailItemsAccessed"
| where UserId == "hr-user@finance.example.com"
| project TimeGenerated, ClientIP, OperationProperties, Folders
```

```kql
// Sharing-link creation by user in the past 7 days
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("AnonymousLinkCreated", "SharingSet", "AddedToGroup")
| project TimeGenerated, UserId, ClientIP, Operation, ObjectId, OfficeWorkload
```

```kql
// Inbox rules created or modified in the past 7 days
OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "Update-InboxRules")
| project TimeGenerated, UserId, ClientIP, Operation, Parameters
```

The `Parameters` field on inbox-rule events contains the rule's actions. An attacker's rule typically forwards mail to an external address or moves all mail to a hidden folder.

Without Sentinel, you can query the same data through `Search-UnifiedAuditLog` in the Exchange Online PowerShell module:

```powershell
Search-UnifiedAuditLog -StartDate "2024-11-12" -EndDate "2024-11-13" `
    -UserIds "hr-user@finance.example.com" `
    -Operations "MailItemsAccessed","FileDownloaded","New-InboxRule" `
    -ResultSize 5000
```

## B.5 OAuth Application Permissions and Service Principals

Attacks through OAuth applications and service principals are worth understanding even if you do not investigate them daily.

A **service principal** is an Entra ID identity for an application. Service principals can hold permissions just like users. They can have credentials in the form of client secrets or certificates, and they can authenticate from anywhere with no MFA.

The compromise pattern:

1. The attacker either creates a new application registration or compromises an existing one
2. The application receives delegated or application-level permissions to read mail, files, directory data, and similar resources
3. The application's client secret or certificate is the persistence mechanism — it bypasses user authentication entirely

Detection signals (audit log):

- `Add application` followed quickly by `Update application – Certificates and secrets management` or `Add service principal credentials`
- Permission grants the application does not need (`Mail.ReadWrite.All`, `Files.ReadWrite.All`, `Directory.Read.All`)
- Sign-in events using the service principal from unexpected IPs (`ServicePrincipalSignInLogs`)

Tools such as AzureHound and ROADtools map application permissions and find privileged service principals the way BloodHound maps AD ACLs. Run them periodically against a tenant to baseline what normal looks like.

## B.6 Conditional Access: What It Tells You After the Fact

Teams usually think of Conditional Access (CA) policies as preventive controls, but they are also forensic data:

- A `ConditionalAccessStatus` of `success` on a sign-in tells you which policies matched and were satisfied
- A `failure` with `RequireMfa` not satisfied is a blocked authentication attempt
- A `notApplied` means no policy matched the sign-in — sometimes intentional, sometimes a coverage gap

When you investigate a compromised account, walk back through its recent sign-ins and note which CA policies *did* and *did not* apply. A sign-in that bypassed CA via a legacy protocol or an excluded service principal is often the entry point.

## B.7 Recovery and Hardening Steps Specific to Cloud Compromise

This section stays brief because this is a forensics book, not an IR runbook:

- **Reset credentials and revoke tokens.** Run `Get-AzureADUser -ObjectId user@domain | Revoke-AzureADUserAllRefreshToken` or its Graph equivalent. Resetting the password is not enough, because existing OAuth tokens remain valid until explicitly revoked.
- **Audit and remove malicious app consent grants.** Use `Get-AzureADUserOAuth2PermissionGrant` and `Remove-AzureADOAuth2PermissionGrant`. The Microsoft *Detect and Remediate Illicit Consent Grants* page documents the full workflow.
- **Audit and remove inbox rules.** Inbox rules are user-scoped and survive password reset. Run `Get-InboxRule -Mailbox user@domain` for each affected mailbox.
- **Audit MFA methods.** An attacker who registered their own MFA method, such as an alternate phone number or an authenticator app on their device, retains access until that method is removed.
- **Audit role assignments and group memberships** for any unexpected additions during the compromise window.
- **Rotate service principal credentials** that the attacker may have created or had access to.

## B.8 Comparison with Other Cloud Identity Providers

The principles in this appendix translate to other providers, though the API names change.

**Google Workspace:** Sign-in events live in the `token` and `login` activities of the Admin SDK Reports API. Drive activity is in the Drive Activity API. App consent and service-account permission changes are in the `admin` activity log.

**Okta:** The `System Log` (`/api/v1/logs`) is the equivalent of Sign-in + Audit logs combined. Pay attention to `user.session.start`, `policy.evaluate_sign_on`, `application.user_membership.add`, and `system.api_token.create` events.

**Generic OAuth providers:** Look for app consent, token grants, refresh-token issuance, and any persistent credential creation against service identities.

## B.9 Pointers for Going Deeper

The single most useful free resource for M365 IR is the CISA *Microsoft 365 / Entra ID Cloud Incident Response Aid*, available from cisa.gov. It walks through exactly the scenarios this appendix introduces.

Mandiant publishes ongoing research on M365 attacker techniques. Its blog posts on *NOBELIUM* / *APT29* tradecraft, such as golden SAML and illicit consent grants, are required reading.

The **Microsoft Entra ID Operations Reference Guide** documents normal vs. anomalous patterns in the Sign-in and Audit logs.

For hands-on experience, CISA's Sparrow and the community-maintained Hawk PowerShell tools automate cloud-incident triage queries. Both are free and open source.

The SANS **FOR509** course (Enterprise Cloud Forensics and Incident Response) is the deepest formal training available on this material as of writing.

---

*End of Appendix B.*

---
