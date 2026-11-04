//! Raw forensic reads for integration tests that deliberately damage storage.
use rusqlite::{Connection, types::Value};
use std::path::Path;

pub fn trigger_sql(connection: &Connection, name: &str) -> String {
    connection
        .query_row(
            "SELECT sql FROM sqlite_schema WHERE type='trigger' AND name=?",
            [name],
            |row| row.get(0),
        )
        .unwrap()
}

pub fn rows(path: &Path) -> Vec<(String, Vec<Vec<Value>>)> {
    let connection = Connection::open(path).unwrap();
    let mut query = connection
        .prepare("SELECT name FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
        .unwrap();
    let tables = query
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    tables
        .into_iter()
        .map(|table| {
            let mut query = connection
                .prepare(&format!("SELECT * FROM {table} ORDER BY rowid"))
                .unwrap();
            let columns = query.column_count();
            let rows = query
                .query_map([], |row| (0..columns).map(|index| row.get(index)).collect())
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
            (table, rows)
        })
        .collect()
}
