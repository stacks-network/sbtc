/*!
# emily-operation-lambda: A lambda for that handles the API requests made to Emily.
*/
/// Event handler that dispatches to other modules.
pub mod eventhandler;
/// Utilities for working with events.
pub mod utils;
/// Emily API Errors.
pub mod errors;
/// Emily API common structures.
pub mod common;
/// Emily operation handlers.
pub mod operations;
