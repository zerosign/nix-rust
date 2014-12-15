use libc;
pub type Pthread = libc::c_ulong;

mod ffi {
    use super::Pthread;
    use libc;

    extern {
        pub fn pthread_self() -> Pthread;
    }
}

pub fn pthread_self() -> Pthread {
    unsafe { ffi::pthread_self() }
}
