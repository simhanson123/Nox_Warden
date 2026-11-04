//! A retained validation belongs to one SQLite connection and read snapshot.
//!
//! A peer commit invalidates the evidence, even if its schema SQL is restored
//! exactly. `data_version` is only a change detector: a changed version always
//! requires complete physical and retained validation before starting live work.
//! Ordinary writes through this connection retain the released SQL guards.
//! Cached evidence contains no quota totals: admission still reads and checks
//! the current database obligations in its own locked writer snapshot.
use super::*;
use rusqlite::hooks::{AuthAction, AuthContext, Authorization, TransactionOperation};
use std::{
    cell::Cell,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

const WRITER_SNAPSHOT_ATTEMPTS: usize = 3;

#[derive(Default)]
struct LocalChanges {
    tainted: AtomicBool,
    in_transaction: AtomicBool,
    #[cfg(test)]
    forensic_arithmetic: AtomicBool,
}

pub(super) struct IntegrityConnection {
    connection: Connection,
    validated: Cell<Option<i64>>,
    local: Arc<LocalChanges>,
    #[cfg(test)]
    validations: Cell<usize>,
}

/// Reading this inside BEGIN establishes the SQLite read snapshot itself.
/// Keep the value read in that snapshot; never refresh it after COMMIT.
pub(super) fn data_version(connection: &Connection) -> Result<i64> {
    Ok(connection.query_row("PRAGMA main.data_version", [], |row| row.get(0))?)
}

fn changes_guards(action: AuthAction<'_>) -> bool {
    match action {
        AuthAction::Read { .. }
        | AuthAction::Select
        | AuthAction::Function { .. }
        | AuthAction::Transaction { .. }
        | AuthAction::Savepoint { .. }
        | AuthAction::Recursive => false,
        AuthAction::Insert { table_name }
        | AuthAction::Delete { table_name }
        | AuthAction::Update { table_name, .. } => {
            matches!(
                table_name,
                "sqlite_master" | "sqlite_schema" | "sqlite_temp_master" | "sqlite_temp_schema"
            )
        }
        AuthAction::Pragma {
            pragma_name,
            pragma_value,
        } => {
            pragma_value.is_some()
                && ![
                    "integrity_check",
                    "quick_check",
                    "foreign_key_check",
                    "table_info",
                    "table_xinfo",
                    "index_info",
                    "index_xinfo",
                    "index_list",
                    "foreign_key_list",
                ]
                .iter()
                .any(|read| pragma_name.eq_ignore_ascii_case(read))
        }
        // DDL, REINDEX, ATTACH and unknown actions cannot be ordinary guarded
        // lifecycle writes. Conservatively stop trusting this connection.
        _ => true,
    }
}

impl IntegrityConnection {
    pub(super) fn from_validated(connection: Connection, validated: Option<i64>) -> Result<Self> {
        let local = Arc::new(LocalChanges::default());
        let observer = local.clone();
        connection.authorizer(Some(move |context: AuthContext<'_>| {
            #[cfg(test)]
            if observer.forensic_arithmetic.load(Ordering::Relaxed) {
                return Authorization::Allow;
            }
            if let AuthAction::Transaction { operation } = context.action {
                match operation {
                    TransactionOperation::Begin => {
                        observer.in_transaction.store(true, Ordering::Relaxed);
                    }
                    // rusqlite maps SQLITE_TRANSACTION's "COMMIT" to Unknown
                    // (its parser names only BEGIN/RELEASE/ROLLBACK).
                    TransactionOperation::Release
                    | TransactionOperation::Rollback
                    | TransactionOperation::Unknown => {
                        observer.in_transaction.store(false, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
            if changes_guards(context.action) {
                // Authorizers run at preparation, not execution. This taint is
                // permanent: a prepared unsafe statement can never outlive a
                // reset of the evidence and execute under a clean cached token.
                observer.tainted.store(true, Ordering::Relaxed);
                if observer.in_transaction.load(Ordering::Relaxed) {
                    return Authorization::Deny;
                }
            }
            Authorization::Allow
        }));
        Ok(Self {
            connection,
            validated: Cell::new(validated),
            local,
            #[cfg(test)]
            validations: Cell::new(0),
        })
    }

    fn snapshot_version(&self, tx: &Transaction<'_>) -> Result<i64> {
        data_version(tx).inspect_err(|_| {
            self.validated.set(None);
        })
    }

    fn validate_transaction(&self, tx: &Transaction<'_>) -> Result<()> {
        #[cfg(test)]
        if self.is_forensic_arithmetic_fixture() {
            return Ok(());
        }
        if self.local.tainted.load(Ordering::Relaxed) {
            self.validated.set(None);
            return Err(invalid("authority live connection schema state changed"));
        }
        // This is the first read in the deferred transaction, binding both the
        // token and complete validation to the same read snapshot.
        let version = self.snapshot_version(tx)?;
        if self.validated.get() != Some(version) {
            // A failed check never leaves a usable token, including repeated
            // attempts against the same damaged external commit.
            self.validated.set(None);
            migrations::validate_v13(tx)?;
            self.validated.set(Some(version));
            #[cfg(test)]
            self.validations.set(self.validations.get() + 1);
        }
        Ok(())
    }

    pub(super) fn transaction(&mut self) -> Result<Transaction<'_>> {
        self.unchecked_transaction_with_behavior(TransactionBehavior::Deferred)
    }

    pub(super) fn transaction_with_behavior(
        &mut self,
        behavior: TransactionBehavior,
    ) -> Result<Transaction<'_>> {
        #[cfg(test)]
        if self.is_forensic_arithmetic_fixture() {
            return Ok(Transaction::new_unchecked(&self.connection, behavior)?);
        }
        if matches!(behavior, TransactionBehavior::Deferred) {
            return self.unchecked_transaction_with_behavior(behavior);
        }
        // Retained replay can grow with lifetime history. Perform it under a
        // read snapshot, allowing unrelated healthy writers to continue. Never
        // upgrade that read transaction: acquire the writer lock separately and
        // accept it only if its first read observes the identical checked token.
        // Retry only changes observed between those snapshots. Each retry can
        // repeat a complete retained check; the bound is attempts, not latency.
        for _ in 0..WRITER_SNAPSHOT_ATTEMPTS {
            {
                let validation =
                    self.unchecked_transaction_with_behavior(TransactionBehavior::Deferred)?;
                if let Err(error) = validation.commit() {
                    self.validated.set(None);
                    return Err(error.into());
                }
            }
            let tx = Transaction::new_unchecked(&self.connection, behavior)?;
            if self.local.tainted.load(Ordering::Relaxed) {
                self.validated.set(None);
                return Err(invalid("authority live connection schema state changed"));
            }
            if self.validated.get() == Some(self.snapshot_version(&tx)?) {
                return Ok(tx);
            }
            self.validated.set(None);
            // Release the writer reservation before the next deferred check.
            drop(tx);
        }
        Err(AuthorityError::Conflict)
    }

    #[allow(dead_code)]
    pub(super) fn unchecked_transaction(&self) -> Result<Transaction<'_>> {
        self.unchecked_transaction_with_behavior(TransactionBehavior::Deferred)
    }

    fn unchecked_transaction_with_behavior(
        &self,
        behavior: TransactionBehavior,
    ) -> Result<Transaction<'_>> {
        let tx = Transaction::new_unchecked(&self.connection, behavior)?;
        self.validate_transaction(&tx)?;
        Ok(tx)
    }

    pub(super) fn query_row<T, P, F>(&self, sql: &str, params: P, map: F) -> rusqlite::Result<T>
    where
        P: rusqlite::Params,
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        self.connection.query_row(sql, params, map)
    }

    /// Only the preexisting arithmetic-only fixture omits intent/job witnesses
    /// and temporarily removes an evidence trigger to model slot transitions.
    /// Its connection is not evidence for retained/live-integrity tests.
    #[cfg(test)]
    pub(super) fn use_forensic_arithmetic_fixture(&mut self) {
        self.local
            .forensic_arithmetic
            .store(true, Ordering::Relaxed);
        self.validated.set(None);
    }

    #[cfg(test)]
    pub(super) fn is_forensic_arithmetic_fixture(&self) -> bool {
        self.local.forensic_arithmetic.load(Ordering::Relaxed)
    }
}

// Existing SQL-guard unit fixtures need raw forensic SQL and hook injection.
// Production has no raw connection/handle, Deref, or hook replacement accessor.
#[cfg(test)]
impl std::ops::Deref for IntegrityConnection {
    type Target = Connection;
    fn deref(&self) -> &Self::Target {
        &self.connection
    }
}

#[cfg(test)]
#[path = "live_integrity_tests.rs"]
mod tests;
