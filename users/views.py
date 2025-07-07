import os
import json
from datetime import datetime, timedelta

from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth import get_user_model, authenticate, login, logout
from django.core.mail import send_mail
from django.utils.crypto import get_random_string
from django.core.cache import cache
from django.conf import settings

from rest_framework import status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import AllowAny

from google.oauth2 import id_token
from google.auth.transport import requests

from .serializers import (
    UserSerializer,
    TokenSerializer,
    UserRegistrationSerializer,
)
from .models import user, Token
from .apis.ocr_endpoint import get_ocr_data
from .apis.fetch_autofill_data import get_autofill_data
from .apis.learning_api import process_with_gemini, enhance_autofill_with_learned_data, process_learned_data_for_display
from .dropbox_storage import DropboxStorage  # import your custom storage


class users_view(viewsets.ModelViewSet):
    serializer_class = UserSerializer
    queryset = user.objects.all()


# Define drop box storage
dropbox_storage = DropboxStorage()

User = get_user_model()


######################  NEW: EMAIL OTP ENDPOINTS ####################


@api_view(["POST"])
@permission_classes([AllowAny])
def send_otp(request):
    print('Inside send_otp function')
    email = request.data.get("email", "").strip().lower()  # normalize

    if not email:
        return Response(
            {"detail": "Email is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    if user.objects.filter(email=email).exists():
        return Response(
            {"detail": "Email is already registered."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    otp = get_random_string(length=6, allowed_chars="0123456789")
    cache.set(f"otp_{email}", otp, timeout=300)

    send_mail(
        subject="Your OTP Code",
        message=f"Your OTP code for Sabapplier AI is {otp}",
        from_email="noreply@sabapplier.com",
        recipient_list=[email],
        fail_silently=False,
    )
    return Response({"detail": "OTP sent."}, status=status.HTTP_200_OK)


@api_view(["POST"])
@permission_classes([AllowAny])
def verify_otp(request):
    print('Inside verify_otp function')
    email = request.data.get("email")
    otp = request.data.get("otp")
    if not (email and otp):
        return Response(
            {"detail": "Email and OTP are required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    real_otp = cache.get(f"otp_{email}")
    if real_otp == otp:
        cache.delete(f"otp_{email}")
        return Response(
            {"detail": "Email verified."}, status=status.HTTP_200_OK
        )

    return Response(
        {"detail": "Invalid OTP."}, status=status.HTTP_400_BAD_REQUEST
    )


# Forgot Password: Send OTP to registered email for password reset
@api_view(["POST"])
@permission_classes([AllowAny])
def send_forgot_password_otp(request):
    print('Inside send_forgot_password_otp function')
    email = request.data.get("email", "").strip().lower()

    if not email:
        return Response(
            {"detail": "Email is required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Check if user exists
    if not user.objects.filter(email=email).exists():
        return Response(
            {"detail": "No account found with this email address."},
            status=status.HTTP_404_NOT_FOUND,
        )

    otp = get_random_string(length=6, allowed_chars="0123456789")
    cache.set(f"reset_otp_{email}", otp, timeout=300)  # 5 minutes

    send_mail(
        subject="Password Reset OTP - Sabapplier AI",
        message=f"Your password reset OTP for Sabapplier AI is {otp}. This OTP is valid for 5 minutes.",
        from_email="noreply@sabapplier.com",
        recipient_list=[email],
        fail_silently=False,
    )
    return Response(
        {"detail": "Password reset OTP sent to your email."},
        status=status.HTTP_200_OK,
    )


# Forgot Password: Verify OTP and reset password
@api_view(["POST"])
@permission_classes([AllowAny])
def reset_password(request):
    print('Inside reset_password function')
    email = request.data.get("email", "").strip().lower()
    otp = request.data.get("otp")
    new_password = request.data.get("password")

    if not all([email, otp, new_password]):
        return Response(
            {"detail": "Email, OTP, and new password are required."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Verify OTP
    real_otp = cache.get(f"reset_otp_{email}")
    if real_otp != otp:
        return Response(
            {"detail": "Invalid or expired OTP."},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # Update password
    try:
        usr = user.objects.get(email=email)
        usr.password = new_password
        usr.save()

        # Delete the OTP after successful password reset
        cache.delete(f"reset_otp_{email}")

        return Response(
            {"success": True, "message": "Password reset successfully."},
            status=status.HTTP_200_OK,
        )
    except user.DoesNotExist:
        return Response(
            {"detail": "User not found."}, status=status.HTTP_404_NOT_FOUND
        )


# Google OAuth signup
@api_view(["POST"])
@permission_classes([AllowAny])
def google_signup(request):
    print('Inside google_signup function')
    try:
        credential = request.data.get("credential")
        if not credential:
            return Response(
                {
                    "success": False,
                    "message": "Google credential is required.",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Verify the Google credential
        try:
            # You'll need to set your Google OAuth client ID in settings
            GOOGLE_CLIENT_ID = getattr(settings, "GOOGLE_CLIENT_ID", None)
            if not GOOGLE_CLIENT_ID:
                return Response(
                    {
                        "success": False,
                        "message": "Google OAuth not configured.",
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

            idinfo = id_token.verify_oauth2_token(
                credential, requests.Request(), GOOGLE_CLIENT_ID
            )

            # Extract comprehensive user data from Google
            email = idinfo.get("email")
            name = idinfo.get("name", "")
            given_name = idinfo.get("given_name", "")
            family_name = idinfo.get("family_name", "")
            picture = idinfo.get("picture", "")
            locale = idinfo.get("locale", "")
            
            # Create a full name from given_name and family_name if name is not available
            if not name and (given_name or family_name):
                name = f"{given_name} {family_name}".strip()

            if not email:
                return Response(
                    {
                        "success": False,
                        "message": "Unable to get email from Google account.",
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Check if user already exists
            try:
                existing_user = user.objects.get(email=email)
                
                # Update existing user with Google data if fields are empty
                updated = False
                if not existing_user.fullName and name:
                    existing_user.fullName = name
                    updated = True
                
                # Update Google profile picture if available
                if picture and not existing_user.google_profile_picture:
                    existing_user.google_profile_picture = picture
                    updated = True
                
                if updated:
                    existing_user.save()
                
                # User exists, check if profile is complete
                profile_complete = all(
                    [
                        existing_user.fullName,
                        existing_user.dateofbirth,
                        existing_user.correspondenceAddress,
                        existing_user.phone_number,
                    ]
                )

                if profile_complete:
                    # User has complete profile, return login data with Google info
                    return Response(
                        {
                            "success": True,
                            "user": UserSerializer(existing_user).data,
                            "needsProfileCompletion": False,
                            "message": "Login successful",
                            "googleData": {
                                "name": name,
                                "email": email,
                                "picture": picture,
                                "given_name": given_name,
                                "family_name": family_name,
                                "locale": locale
                            }
                        },
                        status=status.HTTP_200_OK,
                    )
                else:
                    # User exists but needs to complete profile
                    return Response(
                        {
                            "success": True,
                            "user": UserSerializer(existing_user).data,
                            "email": email,
                            "needsProfileCompletion": True,
                            "message": "Please complete your profile",
                            "googleData": {
                                "name": name,
                                "email": email,
                                "picture": picture,
                                "given_name": given_name,
                                "family_name": family_name,
                                "locale": locale
                            }
                        },
                        status=status.HTTP_200_OK,
                    )

            except user.DoesNotExist:
                # Create new user with Google data
                new_user = user.objects.create(
                    email=email,
                    fullName=name,
                    google_profile_picture=picture,  # Store Google profile picture
                    password="",  # Placeholder password for Google users
                )

                return Response(
                    {
                        "success": True,
                        "user": UserSerializer(new_user).data,
                        "email": email,
                        "needsProfileCompletion": True,
                        "message": "Account created successfully. Please complete your profile.",
                        "googleData": {
                            "name": name,
                            "email": email,
                            "picture": picture,
                            "given_name": given_name,
                            "family_name": family_name,
                            "locale": locale
                        }
                    },
                    status=status.HTTP_201_CREATED,
                )

        except ValueError as e:
            return Response(
                {
                    "success": False,
                    "message": f"Invalid Google token: {str(e)}",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

    except Exception as e:
        return Response(
            {"success": False, "message": f"Google signup failed: {str(e)}"},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR,
        )


######################  API End Points for Website UI ####################


@api_view(["POST"])
@permission_classes([AllowAny])
def register(request):
    print('Inside register function')
    # Ignore extra fields and only process email and password (and confirmPassword if present)
    allowed_fields = {"email", "password", "confirmPassword"}
    data = {k: v for k, v in request.data.items() if k in allowed_fields}
    if (
        "confirmPassword" in data
        and data["password"] != data["confirmPassword"]
    ):
        return Response(
            {"success": False, "message": "Passwords do not match."},
            status=status.HTTP_400_BAD_REQUEST,
        )
    serializer = UserSerializer(data=data)
    if serializer.is_valid():
        serializer.save()
        return Response(
            {
                "success": True,
                "message": "You are now registered on our website!",
            },
            status=status.HTTP_200_OK,
        )
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(["POST"])
@permission_classes([AllowAny])
def update_data(request):
    print('Inside update_data function')
    try:
        userData = request.data.copy()
        
        # Map frontend field names to backend model field names
        if 'address' in userData:
            userData['correspondenceAddress'] = userData.pop('address')
        if 'fullname' in userData:
            userData['fullName'] = userData.pop('fullname')
            
        usr = user.objects.filter(email=userData.get("email", "")).first()
        if not usr:
            return Response(
                {"success": False, "message": "User not found."},
                status=status.HTTP_404_NOT_FOUND,
            )

        if "password" in userData:
            userData.pop("password")
        # Initialize documents and document_texts if not already set
        if usr.document_urls is None:
            usr.document_urls = {}
        if usr.document_texts is None:
            usr.document_texts = {}

        # Handle file uploads
        for field_name, uploaded_file in request.FILES.items():
            
            # Ensure field_name ends with _file_url for consistency
            if not field_name.endswith('_file_url'):
                field_name = field_name + '_file_url'
            
            ext = uploaded_file.name.split('.')[-1]
            base_folder = f"{usr.email.split('@')[0]}"
            # Create clean file name for Dropbox storage
            clean_field_name = field_name.replace('_file_url', '')
            file_name = f"{base_folder}_{clean_field_name}"
            file_path = os.path.join(base_folder, file_name + "."+ ext)

            try:
                # Save to Dropbox
                saved_path = dropbox_storage.save(file_path, uploaded_file)
                file_url = dropbox_storage.url(saved_path)

                # Store in documents with the correct field name that frontend expects
                usr.document_urls[field_name] = file_url

                # Extract and store OCR text
                try:
                    ocr_text = get_ocr_data(uploaded_file)
                    text_field_name = field_name.replace('_file_url', '_text_data')
                    usr.document_texts[text_field_name] = ocr_text
                except Exception as ocr_error:
                    # Store empty text if OCR fails
                    text_field_name = field_name.replace('_file_url', '_text_data')
                    usr.document_texts[text_field_name] = ""
                
            except Exception as upload_error:
                return Response(
                    {"success": False, "message": f"File upload failed: {str(upload_error)}"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )
            
            # Remove file field from userData to avoid serializer issues
            if field_name in userData:
                userData.pop(field_name)

        # Save user instance with updated documents
        usr.save()
        serializer = UserSerializer(usr, data=userData, partial=True)
        if serializer.is_valid():
            serializer.save()
            # Return updated user data
            updated_user_data = UserSerializer(usr).data
            return Response(
                {
                    "success": True, 
                    "message": "Profile updated successfully.",
                    "user_data": updated_user_data
                },
                status=status.HTTP_200_OK,
            )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    except Exception as err:
        return Response(
            {
                "success": False,
                "message": "An error occurred while updating the data.",
            },
            status=status.HTTP_400_BAD_REQUEST,
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def delete_data(request):
    print('Inside delete_data function')
    try:
        userData = request.data.copy()
        usr = user.objects.filter(email=userData.get("email", "")).first()
        field = request.data.get("field")

        if not field:
            return Response(
                {"error": "Field name required."},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if field in usr.document_urls:
            del usr.document_urls[field]
            del usr.document_texts[field.replace("_file_url", "_text_data")]
            usr.save()
            return Response(
                {"success": True, "message": f"{field} deleted."},
                status=status.HTTP_200_OK,
            )
        else:
            return Response(
                {"error": "Invalid field."}, status=status.HTTP_400_BAD_REQUEST
            )
    except Exception as e:
        return Response(
            {"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def login_view(request):
    print('Inside login_view function')
    email = request.data.get("email")
    password = request.data.get("password")
    try:
        usr = user.objects.get(email=email)
        if (usr is None) or (usr.password != password):
            return Response(
                {
                    "success": False,
                    "message": "Invalid user Credentials!",
                },
                status=status.HTTP_401_UNAUTHORIZED,
            )
        else:
            return Response(
                {"success": True, "message": "You are now logged in!"},
                status=status.HTTP_200_OK,
            )
    except user.DoesNotExist:
        return Response(
            {"success": False, "message": "User does not exist"},
            status=status.HTTP_404_NOT_FOUND,
        )


@api_view(["POST"])
@permission_classes([AllowAny])
def logout_view(request):
    print('Inside logout_view function')
    try:
        request.session.flush()
        return Response(
            {"message": "Logout successful"}, status=status.HTTP_200_OK
        )
    except:
        return Response(
            {"error": "Logout failed"}, status=status.HTTP_400_BAD_REQUEST
        )


@api_view(["GET"])
@permission_classes([AllowAny])
def get_profile(request):
    print('Inside get_profile function')
    try:
        usr = user.objects.get(email=request.GET.get("email"))
        serializer = UserSerializer(usr)
        user_data = serializer.data
        return Response(
            {
                "message": "Profile fetched successfully",
                "user_data": user_data,
            },
            status=status.HTTP_200_OK,
        )
    except Exception as err:
        return Response(
            {"error": "profile failed to load"},
            status=status.HTTP_400_BAD_REQUEST,
        )


####################  API End Points for Extension ####################

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def extension_login_view(request):
    print('Inside extension_login_view function')
    try:
        email = request.data.get("user_email")
        password = request.data.get("user_password")
        
        if not email or not password:
            return Response(
                {
                    "success": False,
                    "message": "Email and password are required!",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
            
        try:
            usr = user.objects.get(email=email)
            
            if usr.password != password:  # Note: In production, use proper password hashing
                return Response(
                    {
                        "success": False,
                        "message": "Invalid credentials!",
                    },
                    status=status.HTTP_401_UNAUTHORIZED,
                )
            user_data = UserSerializer(usr).data
            
            return Response(
                {
                    "message": "Login successful",
                    "success": True,
                    "user_name": usr.fullName,
                    "user_email": usr.email,
                    "user_info": user_data,
                },
                status=status.HTTP_200_OK,
            )
            
        except user.DoesNotExist:
            return Response(
                {"success": False, "message": "User does not exist"},
                status=status.HTTP_404_NOT_FOUND,
            )
            
    except Exception as err:
        return Response(
            {"error": f"Login Failed: {str(err)}"},
            status=status.HTTP_400_BAD_REQUEST
        )

@csrf_exempt
@api_view(["POST"])
@permission_classes([AllowAny])
def auto_fill_extension(request):
    print('Inside auto_fill_extension function')
    try:
        html_data = request.data["html_data"]
        user_email = request.data["user_email"]
        try:
            usr = user.objects.get(email=user_email)
            user_data = UserSerializer(usr).data
            autofill_data = get_autofill_data(html_data, user_data)
            print("\nautofill_data:", autofill_data)
            return Response(
                {
                    "message": "Auto-fill successful",
                    "autofill_data": autofill_data,
                },
                status=status.HTTP_200_OK,
            )
        except user.DoesNotExist:
            return Response(
                {"message": "User not found", "autofill_data": {}},
                status=status.HTTP_404_OK,
            )
    except Exception as err:
        return Response(
            {"error": "Auto-fill failed"}, status=status.HTTP_400_BAD_REQUEST
        )

@api_view(['POST'])
@permission_classes([AllowAny])
def save_learned_form_data(request):
    """
    Save learned form data from user interactions
    """
    try:
        print(f"Received save_learned_form_data request: {request.data}")
        user_email = request.data.get('user_email')
        form_data = request.data.get('form_data')  # Raw input data from page
        current_url = request.data.get('current_url') or request.data.get('url')
        
        if not user_email or not form_data:
            return Response({
                "success": False, 
                "message": "Missing required data"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        # Handle both object and array formats from frontend
        if isinstance(form_data, list):
            # Convert array format back to object format for consistency
            form_data_obj = {}
            for item in form_data:
                if isinstance(item, dict):
                    for key, value in item.items():
                        if key != 'type':
                            form_data_obj[key] = value
            form_data = form_data_obj
        
        usr = user.objects.get(email=user_email)
        
        # Initialize extra_details if not exists
        if usr.extra_details is None:
            usr.extra_details = []
        
        # Add new learned data
        learned_entry = {
            "url": current_url,
            "form_data": form_data,
            "timestamp": datetime.now().isoformat(),
            "processed": False  # Flag to indicate if Gemini has processed this
        }
        
        usr.extra_details.append(learned_entry)
        usr.save()
        
        return Response({
            "success": True, 
            "message": "Form data saved for learning"
        }, status=status.HTTP_200_OK)
        
    except user.DoesNotExist:
        return Response({
            "success": False, 
            "message": "User not found"
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as err:
        print(f"Error saving learned data: {err}")
        return Response({
            "success": False, 
            "message": str(err)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def process_learned_data(request):
    """
    Process learned data with Gemini AI to convert to structured format
    """
    try:
        user_email = request.data.get('user_email')
        
        if not user_email:
            return Response({
                "success": False, 
                "message": "User email required"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.get(email=user_email)
        
        if not usr.extra_details:
            return Response({
                "success": False, 
                "message": "No learned data to process"
            }, status=status.HTTP_404_NOT_FOUND)
        
        processed_count = 0
        
        # Process unprocessed entries
        for entry in usr.extra_details:
            if not entry.get('processed', False):
                # Send to Gemini for better formatting
                processed_data = process_with_gemini(entry['form_data'])
                if processed_data:
                    entry['processed_data'] = processed_data
                    entry['processed'] = True
                    processed_count += 1
        
        usr.save()
        
        return Response({
            "success": True, 
            "message": f"Processed {processed_count} learned data entries",
            "processed_count": processed_count
        }, status=status.HTTP_200_OK)
        
    except user.DoesNotExist:
        return Response({
            "success": False, 
            "message": "User not found"
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as err:
        print(f"Error processing learned data: {err}")
        return Response({
            "success": False, 
            "message": str(err)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_learned_data(request):
    """
    Get user's learned form data with enhanced processing
    """
    try:
        user_email = request.GET.get('user_email')
        
        if not user_email:
            return Response({
                "success": False, 
                "message": "User email required"
            }, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.get(email=user_email)
        
        if not usr.extra_details:
            return Response({
                "success": True, 
                "learned_data": [],
                "processed_data": [],
                "count": 0
            }, status=status.HTTP_200_OK)
        
        # Use the new processing function from learning_api
        processed_entries = process_learned_data_for_display(usr.extra_details)
        
        return Response({
            "success": True, 
            "learned_data": usr.extra_details,  # Original data
            "processed_data": processed_entries,  # Processed for frontend
            "count": len(processed_entries)
        }, status=status.HTTP_200_OK)
        
    except user.DoesNotExist:
        return Response({
            "success": False, 
            "message": "User not found"
        }, status=status.HTTP_404_NOT_FOUND)
    except Exception as err:
        print(f"Error getting learned data: {err}")
        return Response({
            "success": False, 
            "message": str(err)
        }, status=status.HTTP_400_BAD_REQUEST)

@api_view(['POST'])
@permission_classes([AllowAny])
def delete_learned_data(request):
    try:
        user_email = request.data.get('user_email')
        index = request.data.get('index')
        
        if not user_email:
            return Response({'success': False, 'error': 'User email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.filter(email=user_email).first()
        if not usr:
            return Response({'success': False, 'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        if usr.extra_details is None:
            usr.extra_details = []
        
        if index is not None and 0 <= index < len(usr.extra_details):
            usr.extra_details.pop(index)
            usr.save()
            return Response({'success': True, 'message': 'Data entry deleted successfully'}, status=status.HTTP_200_OK)
        else:
            return Response({'success': False, 'error': 'Invalid index'}, status=status.HTTP_400_BAD_REQUEST)
            
    except Exception as e:
        print(f"Error deleting learned data: {e}")
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# New view functions for popup mode and smart comparison

@api_view(['POST'])
@permission_classes([AllowAny])
def toggle_popup_mode(request):
    try:
        user_email = request.data.get('user_email')
        enabled = request.data.get('enabled', False)
        
        if not user_email:
            return Response({'success': False, 'error': 'User email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.filter(email=user_email).first()
        if not usr:
            return Response({'success': False, 'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Store popup mode preference in user's extra_details
        if usr.extra_details is None:
            usr.extra_details = []
        
        # Find existing popup mode setting or create new one
        popup_setting = None
        for i, detail in enumerate(usr.extra_details):
            if isinstance(detail, dict) and detail.get('type') == 'popup_mode':
                popup_setting = i
                break
        
        if popup_setting is not None:
            usr.extra_details[popup_setting]['enabled'] = enabled
            usr.extra_details[popup_setting]['last_updated'] = datetime.now().isoformat()
        else:
            usr.extra_details.append({
                'type': 'popup_mode',
                'enabled': enabled,
                'created_at': datetime.now().isoformat(),
                'last_updated': datetime.now().isoformat()
            })
        
        usr.save()
        
        # Log the action for debugging
        print(f"Popup mode {'enabled' if enabled else 'disabled'} for user: {user_email}")
        
        return Response({
            'success': True, 
            'enabled': enabled,
            'message': f'Popup mode {"enabled" if enabled else "disabled"} successfully',
            'timestamp': datetime.now().isoformat()
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"Error toggling popup mode: {e}")
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_popup_mode(request):
    try:
        user_email = request.GET.get('user_email')
        
        if not user_email:
            return Response({'success': False, 'error': 'User email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.filter(email=user_email).first()
        if not usr:
            return Response({'success': False, 'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Default to disabled if no setting found
        enabled = False
        last_updated = None
        
        if usr.extra_details:
            for detail in usr.extra_details:
                if isinstance(detail, dict) and detail.get('type') == 'popup_mode':
                    enabled = detail.get('enabled', False)
                    last_updated = detail.get('last_updated')
                    break
        
        return Response({
            'success': True,
            'enabled': enabled,
            'last_updated': last_updated,
            'user_email': user_email
        }, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"Error getting popup mode: {e}")
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_user_autofill_data(request):
    try:
        user_email = request.GET.get('user_email')
        
        if not user_email:
            return Response({'success': False, 'error': 'User email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.filter(email=user_email).first()
        if not usr:
            return Response({'success': False, 'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get user's autofill data
        autofill_data = get_autofill_data(usr)
        
        # Add metadata for better tracking
        response_data = {
            'success': True,
            'autofill_data': autofill_data,
            'user_email': user_email,
            'data_count': len(autofill_data) if autofill_data else 0,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"Retrieved {len(autofill_data) if autofill_data else 0} autofill data points for user: {user_email}")
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"Error getting user autofill data: {e}")
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['POST'])
@permission_classes([AllowAny])
def compare_form_data(request):
    try:
        user_email = request.data.get('user_email')
        form_data = request.data.get('form_data', [])
        current_url = request.data.get('url', '')
        
        if not user_email:
            return Response({'success': False, 'error': 'User email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.filter(email=user_email).first()
        if not usr:
            return Response({'success': False, 'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get user's existing autofill data
        existing_autofill_data = get_autofill_data(usr)
        
        # Create a mapping of field names to values from existing autofill data
        existing_field_values = {}
        for field_data in existing_autofill_data:
            for field_name, field_value in field_data.items():
                if field_name != 'type' and field_value:
                    # Normalize field name for comparison (remove brackets, quotes, etc.)
                    normalized_name = field_name.replace('[', '').replace(']', '').replace("'", '').replace('"', '').replace('name=', '').replace('#', '').replace('.', '')
                    existing_field_values[normalized_name] = field_value
        
        # Find form data that differs from existing autofill data
        different_data = []
        new_fields = []
        updated_fields = []
        
        for field_data in form_data:
            for field_name, field_value in field_data.items():
                if field_name != 'type' and field_value and field_value.strip():
                    # Normalize field name for comparison
                    normalized_name = field_name.replace('[', '').replace(']', '').replace("'", '').replace('"', '').replace('name=', '').replace('#', '').replace('.', '')
                    
                    # Check if this field exists in existing data
                    if normalized_name in existing_field_values:
                        existing_value = existing_field_values[normalized_name]
                        # If values are different, include this field
                        if existing_value != field_value:
                            different_data.append(field_data)
                            updated_fields.append({
                                'field': normalized_name,
                                'old_value': existing_value,
                                'new_value': field_value
                            })
                            break
                    else:
                        # This is a new field that doesn't exist in autofill data
                        different_data.append(field_data)
                        new_fields.append(normalized_name)
                        break
        
        # Enhanced response with more detailed information
        response_data = {
            'success': True,
            'different_data': different_data,
            'total_form_fields': len(form_data),
            'different_fields': len(different_data),
            'existing_fields_count': len(existing_field_values),
            'new_fields_count': len(new_fields),
            'updated_fields_count': len(updated_fields),
            'new_fields': new_fields,
            'updated_fields': updated_fields,
            'user_email': user_email,
            'current_url': current_url,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"Form comparison for {user_email}: {len(different_data)} different fields out of {len(form_data)} total fields")
        
        return Response(response_data, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"Error comparing form data: {e}")
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@api_view(['GET'])
@permission_classes([AllowAny])
def get_user_stats(request):
    try:
        user_email = request.GET.get('user_email')
        
        if not user_email:
            return Response({'success': False, 'error': 'User email is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        usr = user.objects.filter(email=user_email).first()
        if not usr:
            return Response({'success': False, 'error': 'User not found'}, status=status.HTTP_404_NOT_FOUND)
        
        # Get user's autofill data
        autofill_data = get_autofill_data(usr)
        
        # Get popup mode status
        popup_enabled = False
        if usr.extra_details:
            for detail in usr.extra_details:
                if isinstance(detail, dict) and detail.get('type') == 'popup_mode':
                    popup_enabled = detail.get('enabled', False)
                    break
        
        # Calculate statistics
        total_data_points = len(autofill_data) if autofill_data else 0
        
        # Group data by website/domain
        website_stats = {}
        if autofill_data:
            for field_data in autofill_data:
                for field_name, field_value in field_data.items():
                    if field_name != 'type' and field_value:
                        # Extract domain from field name or use default
                        domain = 'Unknown'
                        if hasattr(field_data, 'url') and field_data.url:
                            try:
                                from urllib.parse import urlparse
                                domain = urlparse(field_data.url).netloc.replace('www.', '')
                            except:
                                domain = 'Unknown'
                        
                        if domain not in website_stats:
                            website_stats[domain] = 0
                        website_stats[domain] += 1
        
        # Get user profile completion stats
        profile_fields = ['fullname', 'email', 'phone', 'address', 'city', 'state', 'pincode']
        completed_fields = sum(1 for field in profile_fields if getattr(usr, field, None))
        profile_completion = (completed_fields / len(profile_fields)) * 100 if profile_fields else 0
        
        stats = {
            'success': True,
            'user_email': user_email,
            'total_data_points': total_data_points,
            'popup_mode_enabled': popup_enabled,
            'profile_completion_percentage': round(profile_completion, 2),
            'websites_count': len(website_stats),
            'website_stats': website_stats,
            'last_activity': usr.updated_at.isoformat() if hasattr(usr, 'updated_at') else None,
            'account_created': usr.created_at.isoformat() if hasattr(usr, 'created_at') else None,
            'timestamp': datetime.now().isoformat()
        }
        
        print(f"Generated stats for user {user_email}: {total_data_points} data points across {len(website_stats)} websites")
        
        return Response(stats, status=status.HTTP_200_OK)
        
    except Exception as e:
        print(f"Error getting user stats: {e}")
        return Response({'success': False, 'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
