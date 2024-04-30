use crate::account::storage::{AccountStorage, AccountStorageBoxed, AccountStorageBuilder, AccountStorageResult};
use mm2_core::mm_ctx::{from_ctx, MmArc};
use std::sync::Arc;

pub(crate) struct AccountContext {
    storage: AccountStorageBoxed,
    db_id: Option<String>,
}

impl AccountContext {
    /// Obtains a reference to this crate context, creating it if necessary.
    pub(crate) fn from_ctx(ctx: &MmArc, db_id: Option<&str>) -> Result<Arc<AccountContext>, String> {
        let account_context = from_ctx(&ctx.account_ctx, move || {
            Ok(AccountContext {
                storage: AccountStorageBuilder::new(ctx, db_id)
                    .build()
                    .map_err(|e| e.to_string())?,
                db_id: db_id.map(|e| e.to_string()),
            })
        })?;

        if account_context.db_id.as_deref() != db_id {
            let mut ctx_field = ctx.account_ctx.lock().unwrap();
            let account_context = Arc::new(AccountContext {
                storage: AccountStorageBuilder::new(ctx, db_id)
                    .build()
                    .map_err(|e| e.to_string())?,
                db_id: db_id.map(|e| e.to_string()),
            });
            *ctx_field = Some(Arc::clone(&account_context) as Arc<dyn std::any::Any + Send + Sync>);

            return Ok(account_context);
        };

        Ok(account_context)
    }

    /// Initializes the storage and returns a reference to it.
    pub(crate) async fn storage(&self) -> AccountStorageResult<&dyn AccountStorage> {
        self.storage.init().await?;
        Ok(self.storage.as_ref())
    }
}
