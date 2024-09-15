use common::stringify_js_error;
use derive_more::Display;
use js_sys::Array;
use mm2_err_handle::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use web_sys::{IdbCursorWithValue, IdbDatabase, IdbIndexParameters, IdbObjectStore, IdbObjectStoreParameters,
              IdbRequest, IdbTransaction};

const ITEM_KEY_PATH: &str = "_item_id";

pub type OnUpgradeResult<T> = Result<T, MmError<OnUpgradeError>>;
pub type OnUpgradeNeededCb = Box<dyn FnOnce(&DbUpgrader, u32, u32) -> OnUpgradeResult<()> + Send>;

#[derive(Debug, Display, PartialEq)]
pub enum OnUpgradeError {
    #[display(fmt = "Error occurred due to creating the '{}' table: {}", table, description)]
    ErrorCreatingTable {
        table: String,
        description: String,
    },
    #[display(fmt = "Error occurred due to opening the '{}' table: {}", table, description)]
    ErrorOpeningTable {
        table: String,
        description: String,
    },
    #[display(fmt = "Error occurred due to creating the '{}' index: {}", index, description)]
    ErrorCreatingIndex {
        index: String,
        description: String,
    },
    #[display(
        fmt = "Upgrade attempt to an unsupported version: {}, old: {}, new: {}",
        unsupported_version,
        old_version,
        new_version
    )]
    UnsupportedVersion {
        unsupported_version: u32,
        old_version: u32,
        new_version: u32,
    },
    #[display(fmt = "Error occurred due to deleting the '{}' table: {}", table, description)]
    ErrorDeletingTable {
        table: String,
        description: String,
    },
    #[display(fmt = "Error occurred while opening the cursor: {}", description)]
    ErrorOpeningCursor {
        description: String,
    },
    #[display(fmt = "Error occurred while adding data: {}", description)]
    ErrorAddingData {
        description: String,
    },
    ErrorGettingKey {
        description: String,
    },
    ErrorGettingValue {
        description: String,
    },
    ErrorAdvancingCursor {
        description: String,
    },
}

pub struct DbUpgrader {
    db: IdbDatabase,
    transaction: IdbTransaction,
}

impl DbUpgrader {
    pub(crate) fn new(db: IdbDatabase, transaction: IdbTransaction) -> DbUpgrader { DbUpgrader { db, transaction } }

    pub fn create_table(&self, table: &str) -> OnUpgradeResult<TableUpgrader> {
        // We use the [in-line](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API/Basic_Concepts_Behind_IndexedDB#gloss_inline_key) primary keys.
        let key_path = JsValue::from(ITEM_KEY_PATH);

        let mut params = IdbObjectStoreParameters::new();
        params.key_path(Some(&key_path));
        params.auto_increment(true);

        match self.db.create_object_store_with_optional_parameters(table, &params) {
            Ok(object_store) => Ok(TableUpgrader { object_store }),
            Err(e) => MmError::err(OnUpgradeError::ErrorCreatingTable {
                table: table.to_owned(),
                description: stringify_js_error(&e),
            }),
        }
    }

    /// Open the `table` if it was created already.
    pub fn open_table(&self, table: &str) -> OnUpgradeResult<TableUpgrader> {
        match self.transaction.object_store(table) {
            Ok(object_store) => Ok(TableUpgrader { object_store }),
            Err(e) => MmError::err(OnUpgradeError::ErrorOpeningTable {
                table: table.to_owned(),
                description: stringify_js_error(&e),
            }),
        }
    }

    /// Deletes an object store (table) from the database.
    pub fn delete_table(&self, table: &str) -> OnUpgradeResult<()> {
        match self.db.delete_object_store(table) {
            Ok(_) => Ok(()),
            Err(e) => MmError::err(OnUpgradeError::ErrorDeletingTable {
                table: table.to_owned(),
                description: stringify_js_error(&e),
            }),
        }
    }
}

pub struct TableUpgrader {
    pub object_store: IdbObjectStore,
}

impl TableUpgrader {
    /// Creates an index.
    /// https://developer.mozilla.org/en-US/docs/Web/API/IDBObjectStore/createIndex
    pub fn create_index(&self, index: &str, unique: bool) -> OnUpgradeResult<()> {
        let mut params = IdbIndexParameters::new();
        params.unique(unique);
        self.object_store
            .create_index_with_str_and_optional_parameters(index, index, &params)
            .map(|_| ())
            .map_to_mm(|e| OnUpgradeError::ErrorCreatingIndex {
                index: index.to_owned(),
                description: stringify_js_error(&e),
            })
    }

    /// Creates an index with the multiple keys.
    /// Each key of the index has to be a field of the table.
    /// Such indexes are used to find records that satisfy constraints imposed on multiple fields.
    /// https://developer.mozilla.org/en-US/docs/Web/API/IDBObjectStore/createIndex
    pub fn create_multi_index(&self, index: &str, fields: &[&str], unique: bool) -> OnUpgradeResult<()> {
        let mut params = IdbIndexParameters::new();
        params.unique(unique);

        let fields_key_path = Array::new();
        for field in fields {
            fields_key_path.push(&JsValue::from(*field));
        }

        self.object_store
            .create_index_with_str_sequence_and_optional_parameters(index, &fields_key_path, &params)
            .map(|_| ())
            .map_to_mm(|e| OnUpgradeError::ErrorCreatingIndex {
                index: index.to_owned(),
                description: stringify_js_error(&e),
            })
    }
}

// #[allow(dead_code)]
// pub async fn copy_store_data(
//     source_store: &IdbObjectStore,
//     target_store: &IdbObjectStore,
// ) -> Result<(), OnUpgradeError> {
//     // Create a oneshot channel to signal when the data transfer is complete
//     let (completion_sender, completion_receiver) = oneshot::channel::<()>();
//
//     // Clone the target store for use in the closure
//     let target_store = target_store.clone();
//
//     // Move completion_sender into the closure
//     let onsuccess_callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
//         let request = event.target().unwrap().unchecked_into::<IdbRequest>();
//         let cursor_result = request.result().unwrap();
//
//         if cursor_result.is_null() || cursor_result.is_undefined() {
//             // No more entries; data transfer complete
//             let _ = completion_sender.send(());
//             return;
//         }
//
//         let cursor = cursor_result.unchecked_into::<IdbCursorWithValue>();
//
//         let key = cursor.key().unwrap();
//         let value = cursor.value().unwrap();
//         target_store.add_with_key(&value, &key).unwrap();
//
//         // Move to the next record
//         cursor.continue_().unwrap();
//     }) as Box<dyn FnMut(_)>);
//
//     // Open the cursor on the source store
//     let cursor_request = source_store.open_cursor().unwrap();
//
//     // Attach the onsuccess callback
//     cursor_request.set_onsuccess(Some(onsuccess_callback.as_ref().unchecked_ref()));
//
//     // Prevent the closure from being dropped
//     onsuccess_callback.forget();
//
//     // Wait for the data transfer to complete
//     completion_receiver.await.unwrap();
//
//     Ok(())
// }

pub fn copy_store_data_sync(
    source_store: &IdbObjectStore,
    target_store: &IdbObjectStore,
) -> Result<(), OnUpgradeError> {
    // Clone the target store for use in the closure
    let target_store = target_store.clone();

    // Define the onsuccess closure
    let onsuccess_callback = Closure::wrap(Box::new(move |event: web_sys::Event| {
        let request = event.target().unwrap().unchecked_into::<IdbRequest>();
        let cursor_result = request.result().unwrap();

        if cursor_result.is_null() || cursor_result.is_undefined() {
            return;
        }

        let cursor = cursor_result.unchecked_into::<IdbCursorWithValue>();

        let key = cursor.key().unwrap();
        let value = cursor.value().unwrap();

        // Insert the data into the target store
        target_store.add_with_key(&value, &key).unwrap();

        // Move to the next record
        cursor.continue_().unwrap();
    }) as Box<dyn FnMut(_)>);

    // Open the cursor on the source store
    let cursor_request = source_store.open_cursor().unwrap();

    // Attach the onsuccess callback
    cursor_request.set_onsuccess(Some(onsuccess_callback.as_ref().unchecked_ref()));

    // Prevent the closure from being dropped
    onsuccess_callback.forget();

    // Note: We cannot block the function here to wait for completion.
    // The transaction will remain open until all requests are completed.

    Ok(())
}
