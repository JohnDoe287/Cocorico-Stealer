from main import UploadFiles, error_handler


@staticmethod
async def upload_file(file_path: str) -> str:
    upload_attempts = [
        ('GoFile', UploadFiles.upload_gofile),
        ('Catbox', UploadFiles.upload_catbox),
        ('File.io', UploadFiles.upload_fileio),
        ('Uguu', UploadFiles.upload_uguu),
        ('KrakenFiles', UploadFiles.upload_krakenfiles),
    ]
    
    for platform, upload_method in upload_attempts:
        try:
            result = await upload_method(file_path)
            if result:
                return result
        except Exception as e:
            error_handler(f"{platform} upload attempt error - {str(e)}")
            continue
    
    return "All upload attempts failed."
