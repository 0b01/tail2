use scraper::Html;

#[tokio::main]
async fn main() {
    let r = reqwest::get("http://ports.ubuntu.com/pool/").await.unwrap();
    let text = r.text().await.unwrap();
    let doc = Html::parse_document(&text);
    let selector = Selector::parse("a").unwrap();
    for element in doc.select(&selector) {
        element.value().name();
    }
}