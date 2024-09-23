use db_common::sqlite::validate_table_name;
use mm2_err_handle::prelude::MmResult;

use super::{WalletConnectStorageError, SESSION_STORAGE_TABLE_NAME};

fn validate_sql_table_name() -> MmResult<String, WalletConnectStorageError> {
    validate_table_name(SESSION_STORAGE_TABLE_NAME)
        .map_err(|err| WalletConnectStorageError::TableError(err.to_string()))?;
    Ok(SESSION_STORAGE_TABLE_NAME.to_owned())
}
