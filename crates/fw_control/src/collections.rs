//! Shared list contract for catalogue, request and enrolled-target projections.
use super::*;
use crate::collection_cursor::{self, CursorClaims, CursorError};
use fw_store::collections::CollectionKind;
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ListQuery {
    pub limit: Option<usize>,
    pub cursor: Option<String>,
    pub eligible: Option<bool>,
}
fn cursor_error(error: CursorError) -> Problem {
    match error {
        CursorError::Expired => Problem(StatusCode::GONE, "CURSOR_EXPIRED"),
        CursorError::Invalid => bad("CURSOR_INVALID"),
        CursorError::Internal => unavailable(),
    }
}
pub(crate) fn page(
    s: &AppState,
    session: &Session,
    q: ListQuery,
    kind: CollectionKind,
    route: &str,
) -> Result<Value, Problem> {
    let at = now();
    if q.eligible.is_some() && !kind.supports_eligibility() {
        return Err(bad("FILTER_UNSUPPORTED"));
    }
    let previous = if let Some(cursor) = q.cursor.as_deref() {
        let claims =
            collection_cursor::decode(cursor, &s.audit_cursor_key, at).map_err(cursor_error)?;
        if claims.org_id != s.tenant.org_id
            || claims.project_id != s.tenant.project_id
            || claims.principal_id != PRINCIPAL
            || claims.session_id != session.id
            || claims.route != route
            || q.limit.is_some_and(|n| n != claims.limit)
            || q.eligible.is_some_and(|v| v != claims.eligible)
        {
            return Err(bad("CURSOR_SCOPE_MISMATCH"));
        }
        Some(claims)
    } else {
        None
    };
    let limit = previous
        .as_ref()
        .map(|c| c.limit)
        .unwrap_or(q.limit.unwrap_or(50));
    if !(1..=100).contains(&limit) {
        return Err(bad("PAGE_LIMIT_INVALID"));
    }
    let eligible = previous
        .as_ref()
        .map(|c| c.eligible)
        .unwrap_or(q.eligible.unwrap_or(false));
    let page = s
        .store
        .list_collection_page(
            &s.tenant,
            kind,
            previous.as_ref().map(|c| c.snapshot.clone()),
            previous.as_ref().map(|c| c.after.clone()),
            limit,
            eligible,
            at,
        )
        .map_err(|e| match e {
            fw_store::StoreError::Conflict("SNAPSHOT_EXPIRED") => {
                Problem(StatusCode::GONE, "CURSOR_EXPIRED")
            }
            fw_store::StoreError::Conflict("ITEM_TOO_LARGE") => {
                Problem(StatusCode::PAYLOAD_TOO_LARGE, "RESULT_TOO_LARGE")
            }
            other => map_store(other),
        })?;
    let mut result = envelope(json!(page.items));
    result["revision"] = json!(
        i32::try_from(
            page.snapshot
                .version
                .checked_add(1)
                .ok_or_else(unavailable)?
        )
        .map_err(|_| unavailable())?
    );
    if matches!(kind, CollectionKind::Assets | CollectionKind::Services) {
        result["freshness"]["source"] = json!("registry");
        result["actions"] = json!([{"action_id":format!("registry.{}.write",kind.name()),"allowed":true,"reason_code":null}]);
    }
    if let Some(after) = page.next_after {
        let claims = CursorClaims {
            schema_version: collection_cursor::SCHEMA.into(),
            org_id: s.tenant.org_id.clone(),
            project_id: s.tenant.project_id.clone(),
            principal_id: PRINCIPAL.into(),
            session_id: session.id.clone(),
            route: route.into(),
            eligible,
            limit,
            issued_at: page.snapshot.issued_at,
            expires_at: page.snapshot.issued_at + fw_store::collections::SNAPSHOT_SECONDS,
            snapshot: page.snapshot,
            after,
        };
        result["next_cursor"] =
            json!(collection_cursor::encode(&claims, &s.audit_cursor_key).map_err(cursor_error)?);
    }
    Ok(result)
}
