pub mod blocking;
pub mod schema;

use blocking::{BlockingHttpClient, HttpScheme};

fn main() {
    let client = BlockingHttpClient::new(HttpScheme::Http, "167.172.25.99", Some(80));

    println!("Service is ready to use!");
}
