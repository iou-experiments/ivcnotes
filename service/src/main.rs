use reqwest::blocking::Client;

pub fn main() {
    let client = Client::new();

    let user = client
        .get("http://167.172.25.99:80/get_user")
        .header("Accept", "*/*")
        .header("content-type", "application/json")
        .body("{\"username\":\"sero\"}")
        .send();

    println!("{:#?}", user.ok());
}
