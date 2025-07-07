import google.generativeai as genai
from datetime import datetime
from django.conf import settings

def process_with_gemini(form_data):
    """
    Process raw form data with Gemini AI to convert it into structured format
    """
    try:
        api_key = "AIzaSyC_OPZO2FLYsAs-Gtvjx-5AQGYKBDUul5k"
        client = genai.configure(api_key=api_key)
        
        prompt = f"""
        Convert this raw form data into a structured format:
        {form_data}
        
        Return a JSON object with:
        - field_name: The semantic name of the field
        - field_type: input/textarea/select/checkbox
        - common_selectors: Array of common CSS selectors for this field
        - sample_values: Array of sample values for this field type
        - field_category: personal_info/education/contact/address/documents/other
        
        Format the response as valid JSON only, no additional text.
        """
        
        response = genai.GenerativeModel('gemini-2.0-flash').generate_content(prompt)
        return response.text
    except Exception as e:
        print(f"Error processing with Gemini: {e}")
        return None

def process_learned_data_for_display(learned_data):
    """
    Process learned data into a format suitable for frontend display
    """
    try:
        if not learned_data or not isinstance(learned_data, list):
            return []
        
        processed_entries = []
        
        for entry in learned_data:
            if not entry.get('form_data'):
                continue
                
            form_data = entry['form_data']
            url = entry.get('url', 'Unknown Site')
            timestamp = entry.get('timestamp', '')
            
            # Extract domain from URL
            domain = get_domain_from_url(url)
            
            # Handle different form_data formats
            if isinstance(form_data, dict):
                # Convert dict format to individual entries
                for selector, value in form_data.items():
                    if selector != 'type':
                        processed_entries.append({
                            'selector': selector,
                            'value': value,
                            'type': form_data.get('type', 'input'),
                            'url': url,
                            'timestamp': timestamp,
                            'domain': domain,
                            'original_entry': entry
                        })
            elif isinstance(form_data, list):
                # Handle array format
                for item in form_data:
                    if isinstance(item, dict):
                        # Find the selector (key that's not metadata)
                        selector = None
                        for key in item.keys():
                            if key not in ["type", "file_name", "file_type", "pixels", "size"]:
                                selector = key
                                break
                        
                        if selector:
                            processed_entries.append({
                                'selector': selector,
                                'value': item[selector],
                                'type': item.get('type', 'input'),
                                'url': url,
                                'timestamp': timestamp,
                                'domain': domain,
                                'file_name': item.get('file_name'),
                                'file_type': item.get('file_type'),
                                'pixels': item.get('pixels'),
                                'size': item.get('size'),
                                'original_entry': entry
                            })
        
        return processed_entries
        
    except Exception as e:
        print(f"Error processing learned data for display: {e}")
        return []

def get_domain_from_url(url):
    """Helper function to extract domain from URL"""
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.netloc.replace('www.', '')
        return domain if domain else 'Unknown Site'
    except:
        return 'Unknown Site'

def enhance_autofill_with_learned_data(html_data, user_data, learned_data):
    """
    Enhance autofill data using learned patterns
    """
    try:
        if not learned_data or not isinstance(learned_data, list):
            return html_data
        
        # Find relevant learned patterns based on current form structure
        relevant_patterns = []
        for entry in learned_data:
            if entry.get('processed_data'):
                relevant_patterns.append(entry['processed_data'])
        
        if not relevant_patterns:
            return html_data
        
        # Create enhanced prompt with learned patterns
        enhanced_prompt = f"""
        Website Text: {html_data}
        User json data: {user_data}
        
        Additionally, the user has learned these form patterns:
        {relevant_patterns}
        
        Use these learned patterns to improve autofill accuracy. 
        For each input field, provide input name (in the format 'input[name='input_name']') 
        or class name (in the format '.class_name') or id (in the format '#id_name') 
        as key and value as its relative user data, also specify input type.
        
        Example format: [{{'input[name='username']': 'demo', 'type': 'input'}}, {{'input[name='email']': 'demoemail@gmail.com', 'type': 'input'}}]
        
        If values are empty don't fill them as null, fill them as NA. 
        For non direct or descriptive field generate relevant response using user data and assign the value.
        Follow order while giving the json, the order should be same as the elements from top to bottom.
        Only output list of json data with key as input html class name and value as user relevant data.
        """
        
        api_key = "AIzaSyC_OPZO2FLYsAs-Gtvjx-5AQGYKBDUul5k"
        client = genai.configure(api_key=api_key)
        response = genai.GenerativeModel('gemini-2.0-flash').generate_content(enhanced_prompt)
        
        autofillData = "".join(response.text.split('\n')[1:-1])
        print('2. Enhanced auto fill data with learned patterns....')
        return autofillData
        
    except Exception as e:
        print(f"Error enhancing autofill: {e}")
        return html_data 