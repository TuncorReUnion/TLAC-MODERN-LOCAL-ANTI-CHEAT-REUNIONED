use anti_cheat::server::AntiCheatServer;

#[tokio::main]
async fn main()
{
    let mut server = AntiCheatServer::new("/tmp/anti-cheat.sock");
    println!("🛡️ TLAC Server başlatılıyor...");
    if let Err(e) = server.run().await
    {
        eprintln!("❌ Server error: {}", e);
    }
}
