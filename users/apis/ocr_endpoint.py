import pytesseract
import cv2
import numpy as np
from pdf2image import convert_from_bytes
from PIL import Image
import io
import google.generativeai as genai
from django.conf import settings
    

def get_structured_data_from_raw_data(raw_data):
    # fetch structured data from ai api using raw data
    api_key = "AIzaSyB5imrkHYR7SEewNu4V1uSPuOTdirjduYs"
    instructions =" I have provided raw data, extract structured data from and format it as a json object and return only json don't generate anything else."
    
    user_prompt = raw_data + instructions   
    client = genai.configure(api_key=api_key)
    response = genai.GenerativeModel('gemini-2.0-flash').generate_content(user_prompt)

    structured_data = "".join(response.text.split('\n')[1:-1])
    print('1. Fetched structured data....')
    return structured_data



def get_ocr_data(uploaded_file):
    uploaded_file.seek(0)
    file_bytes = uploaded_file.read()
    text_output = ""

    def image_to_text(img):
        return pytesseract.image_to_string(img, lang='eng')

    if uploaded_file.name.lower().endswith(".pdf"):
        try:
            # Convert PDF to a list of PIL Image objects
            images = convert_from_bytes(file_bytes, dpi=200)
            for img in images:
                text_output += image_to_text(img) + " "
        except Exception as e:
            print(f"Error processing PDF: {e}")
            text_output = ""
    else:
        # Handle image files
        try:
            img = Image.open(io.BytesIO(file_bytes))
            text_output = image_to_text(img)
        except Exception as e:
            print(f"Error processing image: {e}")
            text_output = ""

    uploaded_file.seek(0) 
    # structured_data = get_structured_data_from_raw_data(text_output.strip())
    data = text_output.strip()
    return data
