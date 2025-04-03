use proc_macro::TokenStream;
use quote::quote;
use syn::{Ident, parse_macro_input};

#[proc_macro]
pub fn test_async(input: TokenStream) -> TokenStream {
    let inner_fn_name = parse_macro_input!(input as Ident);
    let wrapper_fn_name = Ident::new(
        &format!("test_{}_wrapper", inner_fn_name),
        inner_fn_name.span(),
    );

    let output = quote! {
        #[tokio::test]
        async fn #wrapper_fn_name() {
            let mut rng = OsRng::default();
            let seed = rng.next_u64();
            eprintln!("Failed with seed: {}", seed); // Nextest prints test output only on fail
            #inner_fn_name(seed).await;
        }
    };

    output.into()
}

#[proc_macro]
pub fn test(input: TokenStream) -> TokenStream {
    let inner_fn_name = parse_macro_input!(input as Ident);
    let wrapper_fn_name = Ident::new(
        &format!("test_{}_wrapper", inner_fn_name),
        inner_fn_name.span(),
    );

    let output = quote! {
        #[test]
        fn #wrapper_fn_name() {
            let mut rng = OsRng::default();
            let seed = rng.next_u64();
            eprintln!("Failed with seed: {}", seed);  // Nextest prints test output only on fail
            #inner_fn_name(seed);
        }
    };

    output.into()
}
