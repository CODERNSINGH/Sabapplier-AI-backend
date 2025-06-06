import io
import requests
# import dropbox
import google.generativeai as genai
from django.conf import settings


# # 1. load file from google drive
# # 2. send file to ocr api and get text (text extraction from images/pdfs) -- ocr.space
# # 3. send user_data to ai api and get autofill data -- Google Gemini

# def get_text_from_ocr(fh, file_name):
#     ocr_url = "https://api.ocr.space/parse/image"
#     payload = {
#         "isOverlayRequired": "true",
#         "apikey": "K84387269988957",
#         "language": "eng",
#     }

#     fh.seek(0)  # Go back to beginning of file before reading
#     files = { 'file': (file_name, fh)}

#     print("🔎 Sending to OCR API...")
#     r = requests.post(ocr_url, files=files, data=payload)
#     response_json = r.json()
#     doc_text = ""
#     for line in response_json['ParsedResults'][0]['TextOverlay']['Lines']:
#         doc_text += line['LineText'] + "\n"
#     return doc_text

# def dropbox_url_to_path(shared_url, dropbox_access_token):
#     """
#     Convert a Dropbox shared URL to a file path for the API.
#     """
#     try:
#         # Get shared link metadata to extract path
#         dbx = dropbox.Dropbox(dropbox_access_token)
#         res = dbx.sharing_get_shared_link_metadata(shared_url)
#         return res.path_lower  # This gives the API-compatible path
#     except Exception as e:
#         print("❌ Failed to get Dropbox path from URL:", e)
#         return None

# def get_fresh_dropbox_access_token():
#     url = "https://api.dropboxapi.com/oauth2/token"
#     data = {
#         "grant_type": "refresh_token",
#         "refresh_token": settings.DROPBOX_REFRESH_TOKEN,
#         "client_id": settings.DROPBOX_CLIENT_ID,
#         "client_secret": settings.DROPBOX_CLIENT_SECRET,
#     }

#     response = requests.post(url, data=data)
#     if response.status_code == 200:
#         return response.json()["access_token"]
#     else:
#         raise Exception("Failed to refresh Dropbox token: " + response.text)

# def get_file_from_dropbox_and_return_ocr_data(file_url):
#     print("📥 Fetching file from Dropbox for OCR...")
#     # Step 0: GET dropbox access token by refreshing it
#     dropbox_access_token = get_fresh_dropbox_access_token()
    
#     file_path = dropbox_url_to_path(file_url, dropbox_access_token)
#     # Step 1: Dropbox Auth
#     dbx = dropbox.Dropbox(dropbox_access_token)

#     # Step 2: Download file to memory
#     try:
#         metadata, response = dbx.files_download(file_path)
#         file_name = metadata.name
#         file_content = io.BytesIO(response.content)
#     except dropbox.exceptions.ApiError as e:
#         print("❌ Dropbox API Error:", e)
#         return ""

#     print(f"📄 File: {file_name} downloaded successfully.")

#     # Step 3: Send to OCR
#     ocr_result = get_text_from_ocr(file_content, file_name)
#     return ocr_result


    

def get_autofill_data(html_data, user_data):
    # fetch autofill data from ai api using html data and user data
    api_key = "AIzaSyC_OPZO2FLYsAs-Gtvjx-5AQGYKBDUul5k"  # old api key

    # using personal api key
    # api_key = "AIzaSyCCGYyt-8pSsDSNKQ5cKgXoyprvzVRZ4f45"  # personal api key of Narendra Singh
    api_input = f"Website Text: {html_data}\nuser json data: {user_data}"
    instructions ="I have provided website html data and user json, for each and every input field provide input name (in the format 'input[name='input_name']') or class name (it should be in the format '.class_name') or class id (it should be in the format '#class_id') of the field (if there are many class names only provide first class name ) as key and value as its relative user data, also specify input type as file or input or textarea or label or checkbox, ex: [  {'input[name='username']': 'demo', 'type': 'input'},  {'input[name='email']': 'demoemail@gmail.com', 'type': 'file' }]. If values are empty don't fill them as null, fill them as NA. For non direct or descriptive field generate relevant response using user data and assign the value. Also follow order while giving the json, the order should be same as the elements from top to bottom. Only output list of json data with key as input html class name and value as user relevant data, don't give extra response except response list of json."
    
    user_prompt = api_input+ instructions   
    client = genai.configure(api_key=api_key)
    response = genai.GenerativeModel('gemini-2.0-flash').generate_content(user_prompt)

    autofillData = "".join(response.text.split('\n')[1:-1])
    print('1. Fetched auto fill data....')
    return autofillData


