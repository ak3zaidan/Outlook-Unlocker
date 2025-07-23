use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::future::Future;
use crate::unlock::main_unlocker;

unsafe fn c_char_to_option_string(s: *const c_char) -> Option<String> {
    if s.is_null() {
        None
    } else {
        Some(CStr::from_ptr(s).to_string_lossy().to_string())
    }
}

fn block_on<F: Future>(future: F) -> F::Output {
    tokio::runtime::Runtime::new()
        .expect("Failed to create Tokio runtime")
        .block_on(future)
}

#[no_mangle]
pub extern "C" fn main_unlocker_ffi(
    account: *const c_char,
    password: *const c_char,
    country: *const c_char,
    proxy: *const c_char,
    funcap_key: *const c_char,
    sms_key: *const c_char,
) -> *mut c_char {
    // Convert C strings to Rust Option<String>
    let account = unsafe { c_char_to_option_string(account) };
    let password = unsafe { c_char_to_option_string(password) };
    let country = unsafe { c_char_to_option_string(country) };
    let proxy = unsafe { c_char_to_option_string(proxy) };
    
    // These keys are required, so we convert them to String directly
    let funcap_key = unsafe {
        if funcap_key.is_null() {
            return CString::new("Error: funcap_key is required").unwrap().into_raw();
        }
        CStr::from_ptr(funcap_key).to_string_lossy().to_string()
    };
    
    let sms_key = unsafe {
        if sms_key.is_null() {
            return CString::new("Error: sms_key is required").unwrap().into_raw();
        }
        CStr::from_ptr(sms_key).to_string_lossy().to_string()
    };

    // Run the main_unlocker function with our arguments
    let result = block_on(main_unlocker(
        account,
        password,
        country,
        proxy,
        funcap_key,
        sms_key,
    ));

    // Convert the result to a JSON string to pass back to Python
    match result {
        Ok(task_result) => {
            let json = serde_json::json!({
                "success": task_result.success,
                "message": task_result.message,
                "retry": task_result.retry,
                "error": task_result.error.map(|e| e.to_string()),
            });
            
            match serde_json::to_string(&json) {
                Ok(json_string) => CString::new(json_string).unwrap().into_raw(),
                Err(e) => CString::new(format!("Error serializing result: {}", e)).unwrap().into_raw(),
            }
        },
        Err(e) => CString::new(format!("Error: {}", e)).unwrap().into_raw(),
    }
}

#[no_mangle]
pub extern "C" fn free_string(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    unsafe {
        drop(CString::from_raw(s));
    }
}
