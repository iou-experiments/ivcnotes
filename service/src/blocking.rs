use ivcnotes::circuit::IVC;
use ivcnotes::service::msg;
use ivcnotes::Error;
use ivcnotes::{circuit::concrete::Concrete, service::Service};
use reqwest::{Method, Url};

pub enum HttpScheme {
    Http,
    Https,
}

enum Path {
    Register,
    GetContact,
    SendNote,
    GetNotes,
}

pub struct BlockingHttpClient {
    scheme: HttpScheme,
    host: String,
    port: Option<u16>,
}

type Field = <Concrete as IVC>::Field;

fn send<Req: serde::Serialize, Res: for<'de> serde::Deserialize<'de>>(
    method: Method,
    url: Url,
    req: &Req,
) -> Result<Res, Error> {
    let client = reqwest::blocking::Client::new();
    let json = serde_json::to_string(&req).unwrap();
    let res = client
        .request(method, url)
        .header("Accept", "*/*")
        .header("Content-Type", "application/json")
        .body(json)
        .send()
        .map_err(|e| Error::Service(format!("Failed to send request: {}", e)))?;
    serde_json::from_reader(res)
        .map_err(|e| Error::Service(format!("Failed to convert response body: {}", e)))
}

impl BlockingHttpClient {
    pub fn new(scheme: HttpScheme, host: &str, port: Option<u16>) -> Self {
        Self {
            scheme,
            host: host.to_string(),
            port,
        }
    }

    fn base(&self) -> Url {
        let scheme = match self.scheme {
            HttpScheme::Http => "http",
            HttpScheme::Https => "https",
        };
        let mut url = Url::parse(&format!("{}://{}", scheme, self.host)).unwrap();
        url.set_port(self.port).unwrap();
        url
    }

    fn path(&self, path: Path) -> Url {
        let mut url = self.base();
        let path = match path {
            Path::Register => "register",
            Path::GetContact => "get_contact",
            Path::GetNotes => "get_notes",
            Path::SendNote => "send_note",
        };
        url.set_path(path);
        url
    }
}

impl Service<Concrete> for BlockingHttpClient {
    fn register(&self, msg: &msg::request::Register<Concrete>) -> Result<(), Error> {
        let path = self.path(Path::Register);
        send(Method::POST, path, msg)
    }

    fn get_contact(
        &self,
        msg: &msg::request::GetContact<Field>,
    ) -> Result<msg::response::Contact<Concrete>, Error> {
        let path = self.path(Path::GetContact);
        send(Method::GET, path, msg)
    }

    fn send_note(&self, msg: &msg::request::SendNote<Concrete>) -> Result<(), Error> {
        let path = self.path(Path::SendNote);
        send(Method::POST, path, msg)
    }

    fn get_notes(
        &self,
        msg: &msg::request::GetNotes<Field>,
    ) -> Result<msg::response::Notes<Concrete>, Error> {
        let path = self.path(Path::GetNotes);
        send(Method::POST, path, msg)
    }
}
