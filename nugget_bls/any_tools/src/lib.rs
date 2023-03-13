

use ark_std::any::Any;

// use std::{any::Any};

pub struct AnyLinkedList {
    fence:
    start: AnyLLPtr,
}

pub type AnyLLPtr = Cell<Option<Box<AnyLL<dyn Any>>>>;

pub struct AnyLL<T: ?Sized + 'static> {
    next: AnyLLPtr,
    any: T,
}

impl AnyLL<dyn Any> {
    pub fn try_fetch<'a,T: 'static>(&'a self) -> Option<&'a T> {
        let mut selfy: &'a Self = self;
        loop {
            if let Some(r) = selfy.any.downcast_ref::<T>() { return Some(r); }
            if selfy.next.is_none() { return None; }
            selfy = selfy.next.as_ref().unwrap()
        }
    }

    pub fn fetch_or_extend<'a,T: 'static,F: FnOnce() -> T>(&'a mut self, init: F) -> &'a T {
        let mut selfy: &'a mut Self = self;
        loop {
            if let Some(r) = selfy.any.downcast_ref::<T>() { return r; }
            if selfy.next.is_none() {
                let b = Box::new(AnyLL { next: None, any: init(), });
                let new = unsafe { core::mem::transmute(&b.any) };  
                selfy.next = Some(b as Box<AnyLL<dyn Any>>);
                return new;
                // We deduce the above code is safe because you could comment
                // the two lines containing new and uncomment the line below:
                // return selfy.next.as_mut().unwrap().any.downcast_ref::<T>().unwrap();
            }
            selfy = selfy.next.as_mut().unwrap()
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
